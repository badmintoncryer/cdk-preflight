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

    let eng: any;
    try {
      eng = regoEngineCached(engine, this.rules, region, account);
    } catch (e) {
      // ルールパックがコンパイルできない = どのテンプレートも検査できない。
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
        });
      } catch (e) {
        // ここで throw を外に出すと CDK は plugin failure として報告するだけで、
        // CLI 経由では violation ゼロのレポートが黙って握り潰される（issue #151）。
        // 「ルールが 1 本も走らなかった」ことを violation として立てて synth を止める。
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
          severity: 'error',
          violatingResources: [{
            resourceLogicalId: d.entity?.logicalId ?? '(unknown)',
            templatePath: st.templatePath,
            locations: [d.propertyPath ?? '(template)'],
          }],
          ...(d.documentationUrl ? { ruleMetadata: { DocumentationUrl: d.documentationUrl } } : {}),
        });
      }
    }

    return { success: violations.length === 0, violations };
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

const regoEngineCache = new Map<string, any>();
function regoEngineCached(engineModule: any, rules: BundledRuleData[], region?: string, account?: string): any {
  const key = `${region ?? ''}|${account ?? ''}|${rules.map((r) => r.id).join(',')}`;
  if (!regoEngineCache.has(key)) {
    const customRules = [
      ...BUNDLED_LIBS.map((l) => ({ name: l.name, content: l.rego })),
      ...rules.map((r) => ({ name: r.id, content: r.rego })),
    ];
    if (region !== undefined) {
      customRules.push(deployEnvironmentModule(region, account));
    }
    regoEngineCache.set(key, new engineModule.RegoEngine({ customRules }));
  }
  return regoEngineCache.get(key);
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
