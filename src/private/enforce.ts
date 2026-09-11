import * as fs from 'fs';
import * as path from 'path';
import {
  App,
  type IPolicyValidationContext,
  type IPolicyValidationPlugin,
  type PolicyValidationPluginReport,
  type PolicyViolation,
} from 'aws-cdk-lib';
import type { IConstruct } from 'constructs';
import { BUNDLED_LIBS, type BundledRuleData } from '../rules.generated';

/* eslint-disable @typescript-eslint/no-require-imports */
/* eslint-disable import/no-extraneous-dependencies -- @aws/cloudformation-validate は
   aws-cdk-lib 同梱コピーを動的解決する設計（依存には載せない）。README/AGENTS.md 参照 */

/**
 * The name of the generated Rego module that carries the deployment
 * environment into rule evaluation.
 */
export const DEPLOY_ENV_MODULE_NAME = '_pf_deploy_environment';

/**
 * Build the generated module defining `deploy_region` for the rule package.
 *
 * Rules must read it as `data.cdk_preflight.deploy_region` (never as a bare
 * variable): the data reference is simply undefined when the module is not
 * injected — the rule body fails and the rule skips — while a bare variable
 * would be a compile error. Injected by the enforce plugin when the app-level
 * region is concrete; the warn mode (CDK built-in plugin) never injects it,
 * so region-dependent rules only fire in enforce mode.
 */
export function deployEnvironmentModule(region: string, accountId?: string): { name: string; content: string } {
  const account = isConcreteAccount(accountId) ? `deploy_account := ${JSON.stringify(accountId)}\n` : '';
  return {
    name: DEPLOY_ENV_MODULE_NAME,
    content: `package cdk_preflight\n\nimport rego.v1\n\ndeploy_region := ${JSON.stringify(region)}\n${account}`,
  };
}

/** Whether the account from the validation context is a concrete 12-digit account id. */
export function isConcreteAccount(accountId: string | undefined): accountId is string {
  return typeof accountId === 'string' && /^\d{12}$/.test(accountId);
}

/**
 * Whether the region from the validation context is a concrete region name
 * (as opposed to undefined, an unresolved token, or a placeholder).
 */
export function isConcreteRegion(region: string | undefined): region is string {
  return typeof region === 'string' && /^[a-z]{2}(-[a-z]+)+-\d+$/.test(region);
}

interface EngineDiagnostic {
  readonly ruleId: string;
  readonly severity: string;
  readonly message: string;
  readonly source?: string;
  readonly entity?: { readonly logicalId?: string };
  readonly propertyPath?: string;
  readonly documentationUrl?: string;
}

/**
 * enforce モード用の内部プラグイン。
 *
 * CDK 組み込みの CloudFormationValidatePlugin は全 finding を warning に丸めるため
 * （aws-cdk-lib 2.267.0 実測、昇格フラグも無効）、同じエンジンを直接呼び、
 * cdk-preflight のルール違反（および strict 時はエンジンのエラークラス）を
 * policy validation の失敗として報告して synth を止める。
 */
export class PreflightEnforcePlugin implements IPolicyValidationPlugin {
  public readonly name = PLUGIN_NAME;

  constructor(
    private readonly rules: BundledRuleData[],
    private readonly strict: boolean,
  ) {}

  public validate(context: IPolicyValidationContext): PolicyValidationPluginReport {
    const engine = loadEngineCached();
    if (!engine) {
      // eslint-disable-next-line no-console
      console.error(
        'cdk-preflight: could not resolve @aws/cloudformation-validate; ' +
        'enforce mode is unavailable and no preflight checks were run. ' +
        'Install it as a devDependency or use the default (warn) mode.',
      );
      return { success: true, violations: [] };
    }

    const region = isConcreteRegion(context.region) ? context.region : undefined;
    const account = isConcreteAccount(context.accountId) ? context.accountId : undefined;
    const ours = new Set(this.rules.map((r) => r.id));
    const violations: PolicyViolation[] = [];

    // 全テンプレートの和集合で刈り込む。テンプレートごとに刈るとエンジンを何度も
    // 作り直すことになり、そちらのコストの方が高くつく（regoEngineCached のコメント参照）。
    const rules = prune(this.rules, templateResourceTypes(context.stackTemplates.map((st) => st.templatePath)));

    // 1 本も残らない = このアプリのリソースに関係するルールが無い。エンジンを組む必要も無い
    // （libs だけを載せたエンジンは violation ルールを持たず、評価時に落ちる）。
    // strict のときは組み込みエンジンの findings を拾う仕事が残るので通常どおり進む。
    if (rules.length === 0 && !this.strict) {
      return { success: true, violations: [] };
    }

    let eng: any;
    try {
      eng = regoEngineCached(engine, rules, region, account);
    } catch (e) {
      // ルールパックがコンパイルできない = どのテンプレートも検査できないので、
      // 全スタックぶん violation を立てる（1 枚ずつの catch には到達しない）。
      return { success: false, violations: context.stackTemplates.map((st) => engineErrorViolation(st, e)) };
    }

    for (const st of context.stackTemplates) {
      let report: any;
      try {
        report = eng.validateDetailed(new engine.TemplateFile(st.templatePath), {
          pseudoParameterOverrides: {
            accountId: context.accountId,
            region: context.region,
          },
          // 組み込みルールは CDK 組み込みの CloudFormationValidatePlugin が同じテンプレートに
          // 対して既に走らせている。strict でなければ結果も使わず捨てているので、丸ごと切る
          // （実測 70 リソース 1 枚で初回 3.27s -> 0.22s）。strict のときだけ必要になる。
          disableBuiltinRules: !this.strict,
        });
      } catch (e) {
        // throw を外に出すと CDK はこの呼び出しを plugin failure（violation ゼロ）として
        // 記録するだけになり、ここまでに集めた違反も後続テンプレートの違反も丸ごと消え、
        // 残るのは `failed: undefined` だけになる（issue #151）。
        // synth を止めるのは installEnforceGate の役目。ここは「どのスタックで何が
        // 起きたか」をレポートに残し、他スタックのルールを走らせ続けるためのもの。
        violations.push(engineErrorViolation(st, e));
        continue;
      }
      for (const d of (report.diagnostics ?? []) as EngineDiagnostic[]) {
        const isOurs = d.source === 'CUSTOM' && ours.has(d.ruleId);
        const isStrictHit = this.strict
          && d.source !== 'CUSTOM'
          && (d.severity === 'ERROR' || d.severity === 'FATAL');
        if (!isOurs && !isStrictHit) continue;
        violations.push({
          ruleName: d.ruleId,
          description: d.message,
          severity: mapSeverity(d.severity),
          violatingResources: [{
            resourceLogicalId: d.entity?.logicalId ?? '(unknown)',
            templatePath: st.templatePath,
            locations: [d.propertyPath ?? '(template)'],
          }],
          ...(d.documentationUrl ? { ruleMetadata: { DocumentationUrl: d.documentationUrl } } : {}),
        });
      }
    }

    // CDK 組み込みの CloudFormationValidatePlugin と同じ判定。warning だけなら
    // レポートには載るが合成は通る（CLI 側は success/failure に関わらず必ず出力する）。
    return { success: violations.every((v) => !BLOCKS_SYNTH.has(String(v.severity))), violations };
  }
}

/** 合成を止める violation severity。 */
const BLOCKS_SYNTH = new Set(['error', 'fatal']);

/**
 * エンジンの severity を policy validation の severity に写す。表は aws-cdk-lib 2.267.0 の
 * CloudFormationValidatePlugin と同一。`repro.method: doc-only` のルールは WARN を出すので
 * warning になり、報告はされるが synth は止めない（証拠が実機のデプロイ失敗ではないため）。
 */
function mapSeverity(severity: string | undefined): string {
  switch (severity) {
    case 'FATAL':
    case 'ERROR':
      return 'error';
    case 'WARN':
      return 'warning';
    case 'INFO':
      return 'informational';
    case 'DEBUG':
      return 'debug';
    default:
      return 'warning';
  }
}

/**
 * ルール評価そのものが失敗したことを表す violation の ruleName。
 * バンドル済みルールの id ではないので `exclude` では消せない（消してよい状態ではない）。
 */
export const ENGINE_ERROR_RULE = 'pf-engine-error';

/** エンジンが投げた値をメッセージに落とす。エンジンは Error ではなく素の文字列を投げることがある。 */
function engineErrorText(e: unknown): string {
  const message = (e as { message?: unknown } | undefined)?.message;
  return typeof message === 'string' && message.length > 0 ? message : String(e);
}

/** 1 枚のテンプレートを検査できなかったことを violation として報告する。 */
function engineErrorViolation(st: { stackConstructPath: string; templatePath: string }, e: unknown): PolicyViolation {
  return {
    ruleName: ENGINE_ERROR_RULE,
    description:
      'cdk-preflight could not evaluate its rules for this template, so no preflight rule ran for it: '
      + engineErrorText(e),
    severity: 'error',
    fix: 'Report this at https://github.com/badmintoncryer/cdk-preflight/issues; '
      + 'to unblock the build meanwhile, use Preflight.apply(app, { enforce: false }).',
    violatingResources: [{
      constructPath: st.stackConstructPath,
      templatePath: st.templatePath,
      locations: ['(template)'],
    }],
  };
}

/** The plugin name recorded in `validation-report.json` for our findings. */
export const PLUGIN_NAME = 'cdk-preflight';

/** The cloud assembly file the CDK writes its validation report to. */
const VALIDATION_REPORT_FILE = 'validation-report.json';

const GATE_INSTALLED = Symbol.for('cdk-preflight.enforceGate');

/**
 * enforce モードの取りこぼしを塞ぐゲートを App に仕込む。
 *
 * CDK CLI 2.1128.1 以降は app に「レポートは CLI が処理する」と伝えたうえで
 * `validation-report.json` を自分で読むが、その絞り込み（toolkit-lib の
 * `filterReportsByStacks`）が violation の constructPath 先頭セグメントを
 * 選択スタックの hierarchicalId と突き合わせるため、`Stage/Stack` 形式になる
 * Stage 内スタックの違反がすべて捨てられ、synth が黙って成功する（issue #113）。
 *
 * そこで synth 完了後にレポートを読み直し、cdk-preflight の違反が残っていれば
 * 自分で報告して synth を止める。ライブラリが自力で報告する経路（素の node 実行、
 * jest、CLI 2.1128.1 未満）では synth が例外を投げるためここには到達せず、
 * 二重報告は起きない。
 */
export function installEnforceGate(scope: IConstruct): void {
  const root = scope.node.root;
  if (!App.isApp(root)) return;
  const app = root as App & { [GATE_INSTALLED]?: boolean };
  if (app[GATE_INSTALLED]) return;
  Object.defineProperty(app, GATE_INSTALLED, { value: true, enumerable: false });

  const synth = app.synth.bind(app);
  let checked = false;
  app.synth = (options?: Parameters<App['synth']>[0]) => {
    const assembly = synth(options);
    if (!checked) {
      checked = true;
      failIfReportUnhandled(assembly.directory);
    }
    return assembly;
  };
}

/**
 * レポートに cdk-preflight の失敗が残っていれば、findings を出力して synth を止める。
 *
 * 判定は cdk-preflight のレポートだけを見る。組み込みエンジンや construct annotation
 * だけが失敗している場合は CLI が正しく扱えるので、こちらは黙って CLI に任せる。
 * 逆に発火するときはレポート全体を出す。ここで synth を止めると CLI 側の出力が
 * 一切走らないため、同時に出ていたはずの他プラグインの finding が消えてしまう。
 */
function failIfReportUnhandled(directory: string): void {
  let pluginReports: any[];
  try {
    const report = JSON.parse(fs.readFileSync(path.join(directory, VALIDATION_REPORT_FILE), 'utf8'));
    pluginReports = report?.pluginReports ?? [];
  } catch {
    // レポートが無い（プラグイン未実行）または壊れている場合は何もしない
    return;
  }
  const failed = pluginReports.some(
    (r) => r?.pluginName === PLUGIN_NAME && r?.conclusion === 'failure',
  );
  if (!failed) return;

  // eslint-disable-next-line no-console
  console.error(formatReports(pluginReports));
  throw new Error(
    'cdk-preflight: validation failed. Fix the findings above, ' +
    "acknowledge them with Validations.of(scope).acknowledge({ id: 'cdk-preflight::<rule-id>' }), " +
    'or exclude the rule via Preflight.apply(app, { exclude: [...] }).',
  );
}

/**
 * CDK 本体のフォーマッタで整形し、CLI と同一の見た目にする。
 * 私有パスなので解決できないことがあり、その場合は最小限の自前整形に落とす
 * （見た目より「落とす」ことを優先する）。
 */
function formatReports(pluginReports: any[]): string {
  const formatter = loadFormatterCached();
  if (formatter) {
    try {
      return formatter.formatValidationReports(process.cwd(), pluginReports).join('\n\n');
    } catch {
      // fall through
    }
  }
  return fallbackFormat(pluginReports);
}

/**
 * CDK 本体のフォーマッタを解決できないときの最小限の整形。
 * 見た目は劣るが、findings を必ず読める形で出すための最後の砦。
 * （テストからも利用するため export している）
 */
export function fallbackFormat(pluginReports: any[]): string {
  const blocks: string[] = [];
  for (const report of pluginReports) {
    for (const violation of report?.violations ?? []) {
      const ackId = String(violation.ruleName).includes('::')
        ? violation.ruleName
        : `${report.pluginName}::${violation.ruleName}`;
      for (const c of violation.violatingConstructs ?? []) {
        blocks.push(
          `${String(violation.severity ?? 'ERROR').toUpperCase()} ${violation.description} (${report.pluginName})\n` +
          `   ${c.constructPath} (${c.cloudFormationResource?.logicalId}) ${c.constructFqn}\n` +
          `   Acknowledge with '${String(ackId).replace(/ /g, '-')}'`,
        );
      }
    }
  }
  return blocks.join('\n\n');
}

// フォーマッタは aws-cdk-lib の私有パスにあり `exports` から見えないため、
// エンジン解決（loadEngine）と同じくパッケージルートからの絶対パスで読み込む。
let cachedFormatter: any | false | undefined;
function loadFormatterCached(): any | undefined {
  if (cachedFormatter === undefined) {
    cachedFormatter = loadFormatter() ?? false;
  }
  return cachedFormatter === false ? undefined : cachedFormatter;
}

/** （テストからも利用するため export している） */
export function loadFormatter(): any | undefined {
  try {
    const libRoot = path.dirname(require.resolve('aws-cdk-lib/package.json'));
    const mod = require(path.join(libRoot, 'core/lib/validation/private/modern-formatter.js'));
    return typeof mod?.formatValidationReports === 'function' ? mod : undefined;
  } catch {
    return undefined;
  }
}

// エンジン（WASM）の初期化は重いため、モジュールレベルでキャッシュする
let cachedEngineModule: any | false | undefined;
function loadEngineCached(): any | undefined {
  if (cachedEngineModule === undefined) {
    cachedEngineModule = loadEngine() ?? false;
  }
  return cachedEngineModule === false ? undefined : cachedEngineModule;
}

// エンジン（WASM）は 1 プロセスに 1 つだけ生かす。作り直す前に free() しないとインスタンスが
// 積み上がり、2 個目以降の構築が超線形に遅くなる（実測: free 無しで 3.8s -> 11.2s -> 22.1s、
// 構築前に free すると 3.5s -> 0.4s）。ルールセットが変わる（Stage ごとに exclude が違う、
// テストで複数アプリを合成する）たびに作り直すので、キャッシュは 1 スロットで足りる。
let cachedRegoEngine: { key: string; engine: any } | undefined;
function regoEngineCached(engineModule: any, rules: BundledRuleData[], region?: string, account?: string): any {
  const key = `${region ?? ''}|${account ?? ''}|${rules.map((r) => r.id).join(',')}`;
  if (cachedRegoEngine?.key !== key) {
    cachedRegoEngine?.engine?.free?.();
    cachedRegoEngine = undefined;
    const customRules = [
      ...BUNDLED_LIBS.map((l) => ({ name: l.name, content: l.rego })),
      ...mergeRuleModules(rules),
    ];
    if (region !== undefined) {
      customRules.push(deployEnvironmentModule(region, account));
    }
    cachedRegoEngine = { key, engine: new engineModule.RegoEngine({ customRules }) };
  }
  return cachedRegoEngine.engine;
}

/** 全ルールに共通の rego ヘッダ。bundle-rules が package 名と import を 1 種類に強制している。 */
const REGO_HEADER = 'package cdk_preflight\n\nimport rego.v1\n';

/**
 * ルールを service ごとに 1 モジュールへまとめる。
 *
 * コンパイル時間はルール本体の量よりモジュール数で効いてくる（実測 1844 ルールを
 * 1 ルール 1 モジュールで載せると約 6.2s、service 単位の 39 モジュールに畳むと約 1.0s）。
 * ルールはもともと全部 `package cdk_preflight` なので、Rego から見れば結合しても
 * しなくても同じ 1 パッケージ——モジュール境界に意味論は無い。したがって畳めるのだが、
 * 裏を返せば「別ルールが同じ名前のヘルパーを定義すると黙って 1 つの規則に合流する」
 * という危険も結合前から存在する。bundle-rules がルール間のトップレベル名衝突を
 * 弾いているのはそのため（共有したい定義は rules/_lib/ に置く）。
 * （テストからも利用するため export している）
 */
export function mergeRuleModules(rules: BundledRuleData[]): { name: string; content: string }[] {
  const byService = new Map<string, string[]>();
  for (const r of rules) {
    const body = r.rego.replace(/^(?:package|import)\s.*\n/gm, '');
    byService.set(r.service, [...byService.get(r.service) ?? [], body]);
  }
  return [...byService].map(([service, bodies]) => ({
    name: `_pf_service_${service}`,
    content: REGO_HEADER + bodies.join('\n'),
  }));
}

/**
 * テンプレート群に出てくるリソースタイプ。刈り込みに使えないテンプレートが 1 枚でもあれば
 * undefined を返し、刈り込みそのものを諦める（何が載っているか分からないまま落とすと、
 * ルールが黙って発火しなくなる = enforce にとって最悪の壊れ方になるため）。
 * （テストからも利用するため export している）
 */
export function templateResourceTypes(templatePaths: string[]): Set<string> | undefined {
  const types = new Set<string>();
  for (const templatePath of templatePaths) {
    let template: any;
    try {
      template = JSON.parse(fs.readFileSync(templatePath, 'utf8'));
    } catch {
      return undefined;
    }
    // Transform（SAM 等）はマクロ展開で別のリソースに化けるので、生のテンプレートから
    // 読めるリソースタイプは当てにならない。
    if (template?.Transform !== undefined) return undefined;
    for (const resource of Object.values(template?.Resources ?? {}) as any[]) {
      // Fn::ForEach などで Type が静的に読めないエントリがあれば諦める。
      if (typeof resource?.Type !== 'string') return undefined;
      types.add(resource.Type);
    }
  }
  return types;
}

/**
 * テンプレートに出てくるリソースタイプに関係するルールだけを選ぶ。
 *
 * エンジンのコンパイル時間はルール数でほぼ決まるので（実測 1844 ルールで約 4.6s、
 * 典型的なアプリに残る 100 ルール前後なら 0.8s 前後）、これが固定費の主な削りどころ。
 * 安全性は meta.resourceTypes の宣言に乗っている: ルールが見るリソースタイプが
 * 宣言から漏れていると刈られて発火しなくなるため、test/rules.test.ts が全ルールについて
 * 「自分の fail テンプレートで刈り残ること」を検査している。
 * （テストからも利用するため export している）
 */
export function prune(rules: BundledRuleData[], types: Set<string> | undefined): BundledRuleData[] {
  if (types === undefined) return rules;
  // 刈る根拠が無いルールは残す: "*"（全リソース型に効くタグ系ルール）と、
  // resourceTypes が空のもの（バンドル済みルールは非空が保証されているので、該当するのは
  // 手で組み立てたルール = テストや将来のテンプレート層ルールだけ）。
  return rules.filter((r) => r.resourceTypes.length === 0
    || r.resourceTypes.includes('*')
    || r.resourceTypes.some((t) => types.has(t)));
}

/**
 * @aws/cloudformation-validate を解決する。
 * 通常は aws-cdk-lib が bundledDependencies として同梱しているコピーに乗る。
 * （テストからも利用するため export している）
 */
export function loadEngine(): any | undefined {
  try {
    return require('@aws/cloudformation-validate');
  } catch {
    // fall through
  }
  try {
    const libPkg = require.resolve('aws-cdk-lib/package.json');
    const engPkg = require.resolve('@aws/cloudformation-validate/package.json', {
      paths: [path.dirname(libPkg)],
    });
    return require(path.dirname(engPkg));
  } catch {
    return undefined;
  }
}
