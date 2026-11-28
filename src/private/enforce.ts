import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  App,
  CloudFormationValidatePlugin,
  type IPolicyValidationContext,
  type IPolicyValidationPlugin,
  type PolicyValidationPluginReport,
  type PolicyViolation,
} from 'aws-cdk-lib';
import type { IConstruct } from 'constructs';
import { forceConditionalBranches, specializeTemplateFile, undecidedConditions } from './conditions';
import { checkQuotas, nestedTemplateFile, type QuotaCheckOptions } from './quota';
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
 * would be a compile error. Injected for every group of stacks whose region is
 * concrete, in enforce mode and (since #433) in observe mode alike.
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
    /** checkQuotas のときだけ渡る */
    private readonly quotas?: Omit<QuotaCheckOptions, 'severity'>,
  ) {}

  public validate(context: IPolicyValidationContext): PolicyValidationPluginReport {
    const violations = [...this.validateRules(context)];
    if (this.quotas) {
      violations.push(...checkQuotas(context, { ...this.quotas, severity: 'error' }));
    }
    // CDK 組み込みの CloudFormationValidatePlugin と同じ判定。warning だけなら
    // レポートには載るが合成は通る（CLI 側は success/failure に関わらず必ず出力する）。
    return { success: violations.every((v) => !BLOCKS_SYNTH.has(String(v.severity))), violations };
  }

  private validateRules(context: IPolicyValidationContext): PolicyViolation[] {
    const engine = loadEngineCached();
    if (!engine) {
      // eslint-disable-next-line no-console
      console.error(
        'cdk-preflight: could not resolve @aws/cloudformation-validate; ' +
        'enforce mode is unavailable and no preflight checks were run. ' +
        'Install it as a devDependency, or use Preflight.apply(app, { enforce: false }) to report through the CDK built-in validator.',
      );
      return [];
    }

    const ours = new Set(this.rules.map((r) => r.id));
    const violations: PolicyViolation[] = [];

    // 全テンプレートの和集合で刈り込む。テンプレートごとに刈るとエンジンを何度も
    // 作り直すことになり、そちらのコストの方が高くつく（regoEngineCached のコメント参照）。
    // CDK の検証コンテキストにはネストしたスタックが入らないので、子テンプレートを自分で足す（#432）。
    const stackTemplates = withNestedStacks(context.stackTemplates);
    const rules = prune(this.rules, templateResourceTypes(stackTemplates.map((st) => st.templatePath)));

    // 1 本も残らない = このアプリのリソースに関係するルールが無い。エンジンを組む必要も無い
    // （libs だけを載せたエンジンは violation ルールを持たず、評価時に落ちる）。
    // strict のときは組み込みエンジンの findings を拾う仕事が残るので通常どおり進む。
    if (rules.length === 0 && !this.strict) {
      return [];
    }

    // deploy_region / deploy_account はエンジンに焼き込むので、環境ごとにスタックを束ねて
    // 1 環境 1 回だけエンジンを組む。アプリ単位の context.region / accountId は全スタックが
    // 同じ環境のときしか入らず、それを使うと環境の違うスタックが 1 つあるだけで
    // リージョン依存のルールが全スタックで黙る。
    for (const group of byEnvironment(stackTemplates)) {
      let eng: any;
      try {
        eng = regoEngineCached(engine, rules, group.region, group.account);
      } catch (e) {
        // ルールパックがコンパイルできない = この環境のどのテンプレートも検査できないので、
        // そのスタックすべてに violation を立てる（1 枚ずつの catch には到達しない）。
        violations.push(...group.stacks.map((st) => engineErrorViolation(st, e)));
        continue;
      }
      const loaded = { rules, region: group.region, account: group.account, strict: this.strict };
      violations.push(...this.validateStacks(engine, eng, group.stacks, ours, loaded));
    }
    return violations;
  }

  private validateStacks(
    engine: any,
    eng: any,
    stacks: IPolicyValidationContext['stackTemplates'],
    ours: Set<string>,
    loaded: LoadedRules,
  ): PolicyViolation[] {
    const violations: PolicyViolation[] = [];
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cdkpf-spec-'));
    try {
      for (const st of stacks) this.validateStack(engine, eng, st, ours, loaded, tmp, violations);
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
    return violations;
  }

  private validateStack(
    engine: any,
    eng: any,
    st: IPolicyValidationContext['stackTemplates'][number],
    ours: Set<string>,
    loaded: LoadedRules,
    tmp: string,
    violations: PolicyViolation[],
  ): void {
    // Condition / Fn::If を既定値で決まる分だけ畳んだテンプレートを検査する（issue #408）。
    // 作られないリソースと通らない分岐に立つ findings は構造上すべて誤検知。
    const checked = specializeTemplateFile(st.templatePath, { region: st.region, accountId: st.accountId }, tmp) ?? st.templatePath;
    const runOn = (e: any, file: string) => validateTemplate(e, new engine.TemplateFile(file), {
      // CDK 組み込みの CloudFormationValidatePlugin と同じく、スタック自身の値を渡す
      pseudoParameterOverrides: {
        accountId: st.accountId,
        region: st.region,
      },
      // 組み込みルールは CDK 組み込みの CloudFormationValidatePlugin が同じテンプレートに
      // 対して既に走らせている。strict でなければ結果も使わず捨てているので、丸ごと切る
      // （実測 70 リソース 1 枚で初回 3.27s -> 0.22s）。strict のときだけ必要になる。
      disableBuiltinRules: !this.strict,
    });
    const run = (e: any) => runOn(e, checked);
    const settle = (e: any) => settledFindings(e, runOn, checked, tmp);
    let report: any;
    let settled: Set<string> | undefined;
    try {
      report = run(eng);
      settled = settle(eng);
    } catch (e) {
      // throw を外に出すと CDK はこの呼び出しを plugin failure（violation ゼロ）として
      // 記録するだけになり、ここまでに集めた違反も後続テンプレートの違反も丸ごと消え、
      // 残るのは `failed: undefined` だけになる（issue #151）。
      // ルールの評価エラー（Rego の実行時エラー）は service モジュール 1 つが落ちただけでも
      // テンプレート全体の評価を止める。これはルール側のバグであってテンプレートの問題では
      // ないので、落ちた service だけ外して他の全ルールを走らせ直し、外したことは warning で
      // 残す。外しても評価できないとき（コンパイル不能・エンジン自体の失敗）だけ synth を止める。
      const retried = retryWithoutFailingServices(engine, run, e, loaded, settle);
      if (!retried) {
        violations.push(engineErrorViolation(st, e));
        return;
      }
      report = retried.report;
      // Fn::If の両枝の判定も外した後のエンジンで（元のエンジンはまた同じ評価エラーで落ちる。#441）
      settled = retried.settled;
      violations.push(skippedServicesViolation(st, retried.skipped, e));
    }
    for (const d of (report.diagnostics ?? []) as EngineDiagnostic[]) {
      const isOurs = d.source === 'CUSTOM' && ours.has(d.ruleId);
      const isStrictHit = this.strict
        && d.source !== 'CUSTOM'
        && (d.severity === 'ERROR' || d.severity === 'FATAL');
      if (!isOurs && !isStrictHit) continue;
      // 既定値で決まらない Fn::If の片方の枝でしか成り立たない指摘は、デプロイで落ちるとは
      // 言い切れないので synth を止めない（issue #276）。消さずに warning として残す。
      const unsettled = isOurs && settled !== undefined && !settled.has(findingKey(d));
      violations.push({
        ruleName: d.ruleId,
        description: unsettled ? `${d.message}${UNSETTLED_NOTE}` : d.message,
        severity: unsettled && BLOCKS_SYNTH.has(mapSeverity(d.severity)) ? 'warning' : mapSeverity(d.severity),
        violatingResources: [{
          resourceLogicalId: d.entity?.logicalId ?? '(unknown)',
          templatePath: st.templatePath,
          locations: [d.propertyPath ?? '(template)'],
        }],
        ...(d.documentationUrl ? { ruleMetadata: { DocumentationUrl: d.documentationUrl } } : {}),
      });
    }
  }
}

/**
 * `enforce: false` のときのクォータ検査。ルールは CDK 組み込みのプラグインに載せるが、
 * クォータはテンプレートの外の話なので別プラグインにし、warning として報告だけする。
 */
export class PreflightQuotaPlugin implements IPolicyValidationPlugin {
  public readonly name = `${PLUGIN_NAME}-quotas`;

  constructor(private readonly quotas: Omit<QuotaCheckOptions, 'severity'>) {}

  public validate(context: IPolicyValidationContext): PolicyValidationPluginReport {
    return { success: true, violations: checkQuotas(context, { ...this.quotas, severity: 'warning' }) };
  }
}

/**
 * スタックと、そのネストしたスタックの子テンプレート（孫以降も）。子は親と同じ環境・同じ
 * construct path で返す。CDK の検証コンテキストはトップレベルのスタックしか持たないので、
 * これを通さないと NestedStack の中のリソースにはどのルールも掛からない（#432）。
 * 子テンプレートの場所は quota.ts の nestedTemplateFile と同じ辿り方で引く。読めないものは飛ばす。
 * （テストからも利用するため export している）
 */
export function withNestedStacks<T extends { templatePath: string }>(stacks: readonly T[]): T[] {
  const out: T[] = [];
  const seen = new Set<string>();
  const visit = (st: T) => {
    const file = path.resolve(st.templatePath);
    if (seen.has(file)) return;
    seen.add(file);
    out.push(st);
    let template: any;
    try {
      template = JSON.parse(fs.readFileSync(st.templatePath, 'utf8'));
    } catch {
      return;
    }
    const dir = path.dirname(st.templatePath);
    for (const r of Object.values<any>(template?.Resources ?? {})) {
      if (r?.Type !== 'AWS::CloudFormation::Stack') continue;
      let child: string | undefined;
      try {
        child = nestedTemplateFile(dir, r);
      } catch {
        child = undefined;
      }
      const childPath = child === undefined ? undefined : path.join(dir, child);
      if (childPath && fs.existsSync(childPath)) visit({ ...st, templatePath: childPath });
    }
  };
  for (const st of stacks) visit(st);
  return out;
}

/**
 * スタックを (リージョン, アカウント) で束ねる。具体的でない値（未指定・トークン）は undefined に
 * 寄せるので、環境非依存のスタックは deploy_region を注入しないエンジンで評価される。
 * （テストからも利用するため export している）
 */
export function byEnvironment<T extends { region?: string; accountId?: string }>(
  stacks: readonly T[],
): { region?: string; account?: string; stacks: T[] }[] {
  const groups = new Map<string, { region?: string; account?: string; stacks: T[] }>();
  for (const st of stacks) {
    const region = isConcreteRegion(st.region) ? st.region : undefined;
    const account = isConcreteAccount(st.accountId) ? st.accountId : undefined;
    const key = `${region ?? ''}|${account ?? ''}`;
    if (!groups.has(key)) groups.set(key, { region, account, stacks: [] });
    groups.get(key)!.stacks.push(st);
  }
  return [...groups.values()];
}

const UNSETTLED_NOTE = ' (reported as a warning: it holds on only one branch of an Fn::If whose condition cannot be decided at synth time)';

/**
 * 指摘の同一性。同じルールでも別のプロパティの指摘は別物として数える（#434）。リストの添字は
 * 枝を倒すと `AWS::NoValue` の要素が抜けてずれるので、数字の段は伏せる。
 */
function findingKey(d: EngineDiagnostic): string {
  const where = (d.propertyPath ?? '').split('.').map((seg) => (/^\d+$/.test(seg) ? '*' : seg)).join('.');
  return `${d.ruleId}|${d.entity?.logicalId ?? ''}|${where}`;
}

/** 決まらない条件がこれ以下なら真偽の全組み合わせ（2^n 通り）を評価する。 */
const EXHAUSTIVE_CONDITIONS = 3;

/**
 * 決まらない条件の真偽の割り当て。条件が少なければ全組み合わせ、多ければ「全部真」「全部偽」と、
 * 1 つだけを反対にした版（2n + 2 通り）。後者は全組み合わせではないので取りこぼしうるが、
 * 全部を同じ側に倒すだけだった頃（#434）よりは、独立した条件の組み合わせを拾う。
 */
export function conditionAssignments(names: string[]): Map<string, boolean>[] {
  const of = (f: (i: number) => boolean) => new Map(names.map((n, i) => [n, f(i)]));
  if (names.length <= EXHAUSTIVE_CONDITIONS) {
    return Array.from({ length: 2 ** names.length }, (_, m) => of((i) => Math.floor(m / 2 ** i) % 2 === 1));
  }
  const out = [of(() => true), of(() => false)];
  names.forEach((_, j) => {
    out.push(of((i) => i !== j));
    out.push(of((i) => i === j));
  });
  return out;
}

/**
 * テンプレートに既定値で決まらない Fn::If が残っているとき、条件名ごとに真偽を割り当てた版を
 * 評価し、どの版でも出た自前ルールの指摘のキーを返す（issue #276、#434）。
 * 全部を真に倒した版と偽に倒した版の 2 つだけでは、独立した条件が 2 つ以上あるとき、どちらでも
 * 鳴るのにデプロイできる組み合わせ（A 偽 × B 真）を見落として synth を止めていた。
 * Fn::If が残っていない・読めない・評価が失敗したときは undefined で、呼び出し側は何も変えない。
 * ponytail: 条件どうしの関係（Off = Not(On) など）は見ないので、ありえない組み合わせも評価する。
 * そこで鳴らない指摘は warning に落ちる（synth を止めない側に倒れる）。
 */
function settledFindings(
  eng: any,
  runOn: (e: any, file: string) => any,
  checked: string,
  tmp: string,
): Set<string> | undefined {
  try {
    const tpl = JSON.parse(fs.readFileSync(checked, 'utf8'));
    const names = undecidedConditions(tpl);
    if (names.length === 0) return undefined;
    let settled: Set<string> | undefined;
    for (const assignment of conditionAssignments(names)) {
      const forced = forceConditionalBranches(tpl, (name) => assignment.get(name) ?? true);
      if (forced === undefined) return undefined;
      const file = path.join(tmp, `${fs.readdirSync(tmp).length}-forced.template.json`);
      fs.writeFileSync(file, JSON.stringify(forced));
      const r = runOn(eng, file);
      const keys = new Set(((r.diagnostics ?? []) as EngineDiagnostic[]).filter((d) => d.source === 'CUSTOM').map(findingKey));
      settled = settled === undefined ? keys : new Set([...settled].filter((k) => keys.has(k)));
      if (settled.size === 0) break;
    }
    return settled;
  } catch {
    return undefined;
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

/** 評価エラーから切り離し直すために要る、エンジンに載せたものの一式。 */
interface LoadedRules {
  readonly rules: BundledRuleData[];
  readonly region?: string;
  readonly account?: string;
  readonly strict: boolean;
}

/** 評価エラーのメッセージに出る、落ちた service モジュールの名前。 */
function failingService(e: unknown): string | undefined {
  return /_pf_service_([A-Za-z0-9_-]+)/.exec(engineErrorText(e))?.[1];
}

/**
 * 評価エラーを起こした service のルールを外したエンジンで評価し直す。外した先でまた別の
 * service が落ちれば、それも外して続ける。service 名がエラーから読めない（＝ルールの
 * 評価エラーではない）とき、または何度外しても通らないときは undefined。
 */
function retryWithoutFailingServices(
  engineModule: any,
  run: (eng: any) => any,
  firstError: unknown,
  loaded: LoadedRules,
  settle: (eng: any) => Set<string> | undefined,
): { report: any; skipped: string[]; settled?: Set<string> } | undefined {
  const skipped: string[] = [];
  let err = firstError;
  for (let attempt = 0; attempt < 5; attempt++) {
    const service = failingService(err);
    if (service === undefined || skipped.includes(service)) return undefined;
    skipped.push(service);
    const kept = loaded.rules.filter((r) => !skipped.includes(r.service));
    // 残りが無い = 外した service しかこのアプリに関係しなかった。strict でなければ走らせるものが無い
    // （ルールの無いエンジンは評価時に落ちる）。strict は組み込みルールの分が残るので諦める。
    if (kept.length === 0) return loaded.strict ? undefined : { report: { diagnostics: [] }, skipped };
    let eng: any;
    try {
      eng = buildRegoEngine(engineModule, kept, loaded.region, loaded.account);
      const report = run(eng);
      return { report, skipped, settled: settle(eng) };
    } catch (e) {
      err = e;
    } finally {
      eng?.free?.();
    }
  }
  return undefined;
}

/** 評価エラーで一部 service のルールを外して検査したことを warning として報告する。 */
function skippedServicesViolation(
  st: { stackConstructPath: string; templatePath: string },
  services: string[],
  e: unknown,
): PolicyViolation {
  return {
    ruleName: ENGINE_ERROR_RULE,
    description:
      `cdk-preflight could not evaluate its ${services.join(', ')} rules on this template `
      + '(a bug in those rules, not a problem in the template), so they were skipped here; '
      + 'every other rule ran: ' + engineErrorText(e),
    severity: 'warning',
    fix: 'Report this at https://github.com/badmintoncryer/cdk-preflight/issues',
    violatingResources: [{
      constructPath: st.stackConstructPath,
      templatePath: st.templatePath,
      locations: ['(template)'],
    }],
  };
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
// ponytail: 環境（リージョン × アカウント）が N 個あるアプリは synth のたびに N 回組み直す。
// 実アプリでは 1〜3 個。重くなったら deploy_region をモジュールではなく入力で渡す形にする。
let cachedRegoEngine: { key: string; engine: any } | undefined;
function regoEngineCached(engineModule: any, rules: BundledRuleData[], region?: string, account?: string): any {
  const key = `${region ?? ''}|${account ?? ''}|${rules.map((r) => r.id).join(',')}`;
  if (cachedRegoEngine?.key !== key) {
    cachedRegoEngine?.engine?.free?.();
    cachedRegoEngine = undefined;
    cachedRegoEngine = { key, engine: buildRegoEngine(engineModule, rules, region, account) };
  }
  return cachedRegoEngine.engine;
}

function buildRegoEngine(engineModule: any, rules: BundledRuleData[], region?: string, account?: string): any {
  const customRules = [
    ...BUNDLED_LIBS.map((l) => ({ name: l.name, content: l.rego })),
    ...mergeRuleModules(rules),
  ];
  if (region !== undefined) {
    customRules.push(deployEnvironmentModule(region, account));
  }
  return new engineModule.RegoEngine({ customRules });
}

// 観測モード（enforce: false）は CDK 組み込みの CloudFormationValidatePlugin に相乗りする。
// あちらはコンストラクタでエンジンを 1 つ作って free() しないので、同じプロセスで App を
// 作り直すたびにインスタンスが積み上がり、regoEngineCached と同じ超線形の悪化を起こす
// （実測 2026-09-13: 同じルールセットで 4 回 synth して 36s -> 95s -> 131s -> 178s）。
// ルールセットが変わらない限りプラグインごと使い回す。
// ponytail: キーが変わったときに古いエンジンは free() しない（エンジンは CDK 側の
// private フィールドで、触るには内部実装に手を入れることになる）。設定違いの Stage が
// N 個あれば N 個積むが、実アプリでは 1〜2 個。積み上がりが問題になるなら、そのときに
// アップストリームへ free/dispose を入れてもらう。
let cachedObservePlugin: { key: string; plugin: ConditionAwarePlugin } | undefined;
export function observePluginCached(rules: BundledRuleData[]): ConditionAwarePlugin {
  const key = rules.map((r) => r.id).join(',');
  if (cachedObservePlugin?.key !== key) {
    const regoRules = [
      ...BUNDLED_LIBS.map((l) => ({ name: l.name, content: l.rego })),
      ...mergeRuleModules(rules),
    ];
    cachedObservePlugin = {
      key,
      plugin: new ConditionAwarePlugin((region, account) => new CloudFormationValidatePlugin({
        regoRules: region === undefined ? regoRules : [...regoRules, deployEnvironmentModule(region, account)],
      })),
    };
  }
  return cachedObservePlugin.plugin;
}

/**
 * 観測モードのプラグイン。中身は CDK 組み込みの CloudFormationValidatePlugin のままで（報告の名前と
 * acknowledge の id は `CloudFormation-Validate::<rule-id>` のまま）、enforce と同じ下ごしらえをする。
 *
 * - Condition / Fn::If を既定値で決まる分だけ畳んだテンプレートを渡し、報告のパスは元に戻す（#408）
 * - ネストしたスタックの子テンプレートも渡す（#432）
 * - スタックを環境（リージョン × アカウント）で束ね、具体的な環境には deploy_region / deploy_account を
 *   焼き込んだ組み込みプラグインを使う。これが無いとリージョン・アカウント依存のルールが観測モードでは
 *   一切評価されない（#433）。環境ごとのプラグインは 1 度作ったら使い回す（エンジンは free() できない）。
 */
export class ConditionAwarePlugin implements IPolicyValidationPlugin {
  public readonly name: string;
  /** 環境を焼き込まないプラグイン（環境が具体的でないスタック用） */
  public readonly inner: CloudFormationValidatePlugin;
  private readonly byEnv = new Map<string, CloudFormationValidatePlugin>();
  constructor(private readonly make: (region?: string, account?: string) => CloudFormationValidatePlugin) {
    this.inner = make();
    this.name = this.inner.name;
  }
  public get version(): string | undefined {
    return this.inner.version;
  }
  public get ruleIds(): string[] | undefined {
    return this.inner.ruleIds;
  }
  public validate(context: IPolicyValidationContext): PolicyValidationPluginReport {
    // enforce と同じくネストしたスタックの子テンプレートも検査させる（#432）
    const groups = byEnvironment(withNestedStacks(context.stackTemplates));
    const reports = groups.map((g) => this.validateGroup(context, g.stacks, this.pluginFor(g.region, g.account)));
    if (reports.length === 1) return reports[0];
    return {
      ...reports[0] ?? {},
      success: reports.every((r) => r.success),
      violations: reports.flatMap((r) => r.violations),
    };
  }

  private pluginFor(region?: string, account?: string): CloudFormationValidatePlugin {
    if (region === undefined) return this.inner;
    const key = `${region}|${account ?? ''}`;
    if (!this.byEnv.has(key)) this.byEnv.set(key, this.make(region, account));
    return this.byEnv.get(key)!;
  }

  private validateGroup(
    context: IPolicyValidationContext,
    stacks: IPolicyValidationContext['stackTemplates'],
    plugin: CloudFormationValidatePlugin,
  ): PolicyValidationPluginReport {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cdkpf-spec-'));
    try {
      const back = new Map<string, string>();
      const stackTemplates = stacks.map((st) => {
        const spec = specializeTemplateFile(st.templatePath, { region: st.region, accountId: st.accountId }, tmp);
        if (spec === undefined) return st;
        back.set(spec, st.templatePath);
        return { ...st, templatePath: spec };
      });
      const report = plugin.validate({
        ...context,
        templatePaths: stackTemplates.map((st) => st.templatePath),
        stackTemplates,
      });
      if (back.size === 0) return report;
      return {
        ...report,
        violations: report.violations.map((v) => ({
          ...v,
          violatingResources: v.violatingResources.map((r) => (r.templatePath && back.has(r.templatePath)
            ? { ...r, templatePath: back.get(r.templatePath)! } : r)),
        })),
      };
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  }
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
/**
 * エンジンの版に依らずテンプレートを評価する。1.7.0-beta〜1.9.0-beta（aws-cdk-lib 2.267〜2.270 の
 * 同梱版）は validateDetailed だけ、1.10.0 は validateTemplate だけ（改名）、1.11.0 以降は両方を
 * 持ち、1.12.1 で validateDetailed は非推奨の別名になった。レポートの形（diagnostics の
 * ruleId/severity/source/propertyPath/entity.logicalId）は両者で同じ（実測 2026-09-28、
 * 1.7.0-beta / 1.10.0 / 1.12.1 で fail テンプレート 400 本の CUSTOM 診断が完全一致）。
 * 先に消えるのは非推奨の側なので validateTemplate を優先する。
 */
export function validateTemplate(eng: any, template: unknown, config: object): any {
  const fn = eng.validateTemplate ?? eng.validateDetailed;
  if (typeof fn !== 'function') {
    throw new Error('@aws/cloudformation-validate has neither validateTemplate nor validateDetailed');
  }
  return fn.call(eng, template, config);
}

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

/**
 * loadEngine() が載せるのと同じエンジンの版。解決順も同じにしてある。読めなければ undefined。
 * （テストからも利用するため export している）
 */
export function engineVersion(): string | undefined {
  try {
    return require('@aws/cloudformation-validate/package.json').version;
  } catch {
    // fall through
  }
  try {
    const libPkg = require.resolve('aws-cdk-lib/package.json');
    return require(require.resolve('@aws/cloudformation-validate/package.json', {
      paths: [path.dirname(libPkg)],
    })).version;
  } catch {
    return undefined;
  }
}

/**
 * semver の大小（a < b で負）。プレリリース（`1.9.0-beta`）は同じ版の正式リリースより小さい。
 * 読めない形なら undefined。
 * ponytail: プレリリース同士は文字列で比べる（エンジンは `-beta` しか出していない）。
 */
export function compareVersions(a: string, b: string): number | undefined {
  const parse = (v: string) => /^(\d+)\.(\d+)\.(\d+)(?:-(.+))?$/.exec(v);
  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) return undefined;
  for (let i = 1; i <= 3; i++) {
    const d = Number(pa[i]) - Number(pb[i]);
    if (d !== 0) return d;
  }
  if (pa[4] === pb[4]) return 0;
  if (pa[4] === undefined) return 1;
  if (pb[4] === undefined) return -1;
  return pa[4] < pb[4] ? -1 : 1;
}

/**
 * このエンジンが自力で止める制約のルールか（meta.yaml#supersededBy）。版が読めなければ false
 * ＝省かない（重複が出るだけで、見逃しは起きない側に倒す）。
 */
export function isSuperseded(rule: BundledRuleData, version: string | undefined): boolean {
  if (!rule.supersededBy || version === undefined) return false;
  return (compareVersions(version, rule.supersededBy.engine) ?? -1) >= 0;
}
