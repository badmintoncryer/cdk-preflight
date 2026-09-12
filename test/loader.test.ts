/**
 * ローダ（Preflight.apply）の CDK 統合テスト。
 * synth を実際に実行し、validation-report.json / 例外で検証する。
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { App, Stack, Stage, Validations, aws_ec2 as ec2, aws_lambda as lambda, aws_logs as logs, aws_sqs as sqs } from 'aws-cdk-lib';
import { Preflight } from '../src';
import {
  ENGINE_ERROR_RULE,
  PreflightEnforcePlugin,
  fallbackFormat,
  installEnforceGate,
  loadFormatter,
  mergeRuleModules,
  prune,
  templateResourceTypes,
} from '../src/private/enforce';
import { BUNDLED_RULES, type BundledRuleData } from '../src/rules.generated';

function tmpOut(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'cdk-preflight-test-'));
}

function makeApp(context: Record<string, unknown> = {}): App {
  return new App({
    outdir: tmpOut(),
    context: { '@aws-cdk/core:validationReportJson': true, ...context },
  });
}

interface ReportViolation {
  ruleName: string;
  severity: string;
}

function readReport(app: App): ReportViolation[] {
  const p = path.join(app.outdir, 'validation-report.json');
  if (!fs.existsSync(p)) return [];
  const report = JSON.parse(fs.readFileSync(p, 'utf8'));
  return report.pluginReports.flatMap((r: any) => r.violations ?? []);
}

/** pf-ec2-sg-port-range に違反する SG（組み込みエンジンは検出しないことを実測済み） */
function addBadSecurityGroup(stack: Stack): void {
  const vpc = new ec2.CfnVPC(stack, 'Vpc', { cidrBlock: '10.0.0.0/16' });
  new ec2.CfnSecurityGroup(stack, 'SG', {
    groupDescription: 'cdk-preflight loader test',
    vpcId: vpc.ref,
    securityGroupIngress: [{ ipProtocol: 'tcp', fromPort: 99999, toPort: 99999, cidrIp: '10.0.0.0/8' }],
  });
}

/**
 * doc-only ルール（pf-lambda-scaling-min-zero-requires-max-zero）に違反する関数。
 * FunctionScalingConfig は L2 を通らないので addPropertyOverride で入れる。
 */
function addDocOnlyViolation(stack: Stack): void {
  const fn = new lambda.CfnFunction(stack, 'F', {
    role: 'arn:aws:iam::123456789012:role/lambda-role',
    code: { zipFile: 'x' },
    runtime: 'python3.13',
    handler: 'index.handler',
  });
  fn.addPropertyOverride('FunctionScalingConfig', {
    MinExecutionEnvironments: 0,
    MaxExecutionEnvironments: 5,
  });
}

/** 組み込みエンジンだけが検出する違反（enum 外の RetentionInDays → W3030） */
function addBuiltInOnlyViolation(stack: Stack): void {
  new logs.CfnLogGroup(stack, 'L', { retentionInDays: 4 });
}

describe('observe mode (enforce: false)', () => {
  test('reports bundled rule violations alongside built-in findings', () => {
    const app = makeApp();
    Preflight.apply(app, { enforce: false });
    const stack = new Stack(app, 'S');
    addBadSecurityGroup(stack);
    addBuiltInOnlyViolation(stack);
    app.synth(); // must not throw
    const rules = readReport(app).map((v) => v.ruleName);
    expect(rules).toContain('pf-ec2-sg-port-range');
    // 組み込みルール（スキーマ enum 検証）が失われていないこと
    expect(rules).toContain('W3030');
  });

  test('clean stacks produce no preflight findings', () => {
    const app = makeApp();
    Preflight.apply(app, { enforce: false });
    const stack = new Stack(app, 'S');
    const vpc = new ec2.CfnVPC(stack, 'Vpc', { cidrBlock: '10.0.0.0/16' });
    new ec2.CfnSecurityGroup(stack, 'SG', {
      groupDescription: 'cdk-preflight loader test',
      vpcId: vpc.ref,
      securityGroupIngress: [{ ipProtocol: 'tcp', fromPort: 443, toPort: 443, cidrIp: '10.0.0.0/8' }],
    });
    app.synth();
    const mine = readReport(app).filter((v) => v.ruleName.startsWith('pf-'));
    expect(mine).toHaveLength(0);
  });

  test('exclude removes a rule', () => {
    const app = makeApp();
    Preflight.apply(app, { enforce: false, exclude: ['pf-ec2-sg-port-range'] });
    addBadSecurityGroup(new Stack(app, 'S'));
    app.synth();
    const rules = readReport(app).map((v) => v.ruleName);
    expect(rules).not.toContain('pf-ec2-sg-port-range');
  });

  test('includeUpstreamPending: false keeps non-pending rules active', () => {
    const app = makeApp();
    Preflight.apply(app, { enforce: false, includeUpstreamPending: false });
    addBadSecurityGroup(new Stack(app, 'S'));
    app.synth();
    const rules = readReport(app).map((v) => v.ruleName);
    // 現在の同梱ルールに pending-engine は無いため、全ルールが有効なまま
    expect(rules).toContain('pf-ec2-sg-port-range');
  });
});

describe('input validation', () => {
  test('rejects unknown rule ids in exclude', () => {
    const app = makeApp();
    expect(() => Preflight.apply(app, { exclude: ['no-such-rule'] })).toThrow(/unknown rule id/);
  });

  test('rejects non-App/Stage scopes', () => {
    const app = makeApp();
    const stack = new Stack(app, 'S');
    expect(() => Preflight.apply(stack as any)).toThrow(/App or a Stage/);
  });
});

describe('enforce mode (default)', () => {
  test('is the default: synthesis fails on a bundled rule violation', () => {
    const app = makeApp();
    Preflight.apply(app);
    addBadSecurityGroup(new Stack(app, 'S'));
    expect(() => app.synth()).toThrow(/pf-ec2-sg-port-range|Validation failed/);
  });

  test('fails synthesis on a bundled rule violation', () => {
    const app = makeApp();
    Preflight.apply(app, { enforce: true });
    addBadSecurityGroup(new Stack(app, 'S'));
    expect(() => app.synth()).toThrow(/pf-ec2-sg-port-range|Validation failed/);
  });

  test('exclude lets an otherwise-violating stack synthesize', () => {
    const app = makeApp();
    Preflight.apply(app, { exclude: ['pf-ec2-sg-port-range'] });
    addBadSecurityGroup(new Stack(app, 'S'));
    expect(() => app.synth()).not.toThrow();
  });

  test('a doc-only rule is reported as a warning and does not fail synthesis', () => {
    const app = makeApp();
    Preflight.apply(app);
    addDocOnlyViolation(new Stack(app, 'S'));
    expect(() => app.synth()).not.toThrow();
    const v = readReport(app).filter((x) => x.ruleName === 'pf-lambda-scaling-min-zero-requires-max-zero');
    expect(v).toHaveLength(1);
    expect(v[0].severity).toBe('warning');
  });

  test('an error-severity rule still fails synthesis when a warning is present too', () => {
    const app = makeApp();
    Preflight.apply(app);
    const stack = new Stack(app, 'S');
    addDocOnlyViolation(stack);
    addBadSecurityGroup(stack);
    expect(() => app.synth()).toThrow(/cdk-preflight/);
  });

  test('passes synthesis for clean stacks', () => {
    const app = makeApp();
    Preflight.apply(app, { enforce: true });
    const stack = new Stack(app, 'S');
    const vpc = new ec2.CfnVPC(stack, 'Vpc', { cidrBlock: '10.0.0.0/16' });
    new ec2.CfnSecurityGroup(stack, 'SG', {
      groupDescription: 'cdk-preflight loader test',
      vpcId: vpc.ref,
      securityGroupIngress: [{ ipProtocol: 'tcp', fromPort: 443, toPort: 443, cidrIp: '10.0.0.0/8' }],
    });
    expect(() => app.synth()).not.toThrow();
  });

  test('strict: true additionally blocks built-in error-class findings', () => {
    const app = makeApp();
    Preflight.apply(app, { enforce: true, strict: true });
    const stack = new Stack(app, 'S');
    // どの pf- ルールにも触れないが、組み込みスキーマ検証がエラークラス（F3034/FATAL）で
    // 検出する値（SQS の範囲はエンジン同梱スキーマに min/max がある）
    new sqs.CfnQueue(stack, 'Q', { visibilityTimeout: 99999 });
    expect(() => app.synth()).toThrow(/Validation failed|F3034|3034/);
  });

  test('strict: true does not block warn-class built-in findings', () => {
    const app = makeApp();
    Preflight.apply(app, { enforce: true, strict: true });
    const stack = new Stack(app, 'S');
    // enum 違反はエンジン上 W3030（WARN クラス）なので strict でもブロックしない
    new logs.CfnLogGroup(stack, 'L', { retentionInDays: 4 });
    expect(() => app.synth()).not.toThrow();
  });

  test('strict: false lets built-in findings stay warnings', () => {
    const app = makeApp();
    Preflight.apply(app, { enforce: true, strict: false });
    const stack = new Stack(app, 'S');
    new sqs.CfnQueue(stack, 'Q', { visibilityTimeout: 99999 });
    expect(() => app.synth()).not.toThrow();
  });
});

describe('enforce gate (CDK CLI takes over validation reporting)', () => {
  // CLI 2.1128.1 以降は app にこのコンテキストを渡してライブラリ側の報告を止め、
  // 自分で validation-report.json を読む。その絞り込みが Stage 内スタックの違反を
  // 取りこぼすため（issue #113）、cdk-preflight 側で synth を止め直す。
  const cliHandlesReporting = { '@aws-cdk/core:failSynthOnValidationErrors': false };
  let stderr: jest.SpyInstance;

  beforeEach(() => {
    stderr = jest.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => {
    stderr.mockRestore();
  });

  test('fails synthesis for a violation inside a Stage', () => {
    const app = makeApp(cliHandlesReporting);
    Preflight.apply(app);
    const stage = new Stage(app, 'MyStage');
    addBadSecurityGroup(new Stack(stage, 'S'));
    expect(() => app.synth()).toThrow(/cdk-preflight: validation failed/);
    expect(stderr.mock.calls.join('\n')).toContain('pf-ec2-sg-port-range');
  });

  test('fails synthesis for a violation in a top-level stack', () => {
    const app = makeApp(cliHandlesReporting);
    Preflight.apply(app);
    addBadSecurityGroup(new Stack(app, 'S'));
    expect(() => app.synth()).toThrow(/cdk-preflight: validation failed/);
  });

  test('reports findings of other plugins too, since the CLI output is preempted', () => {
    const app = makeApp(cliHandlesReporting);
    Preflight.apply(app);
    const stack = new Stack(app, 'S');
    addBadSecurityGroup(stack);
    addBuiltInOnlyViolation(stack);
    expect(() => app.synth()).toThrow(/cdk-preflight: validation failed/);
    const printed = stderr.mock.calls.join('\n');
    expect(printed).toContain('pf-ec2-sg-port-range');
    expect(printed).toContain('W3030');
  });

  test('stays silent when only other plugins have findings', () => {
    const app = makeApp(cliHandlesReporting);
    Preflight.apply(app);
    // 組み込みエンジンだけが出す finding は CLI が正しく扱えるので、こちらは介入しない
    addBuiltInOnlyViolation(new Stack(app, 'S'));
    expect(() => app.synth()).not.toThrow();
    expect(stderr).not.toHaveBeenCalled();
  });

  test('passes clean apps', () => {
    const app = makeApp(cliHandlesReporting);
    Preflight.apply(app);
    new Stack(app, 'S');
    expect(() => app.synth()).not.toThrow();
  });

  test('an acknowledged finding does not fail synthesis', () => {
    const app = makeApp(cliHandlesReporting);
    Preflight.apply(app);
    const stage = new Stage(app, 'MyStage');
    const stack = new Stack(stage, 'S');
    addBadSecurityGroup(stack);
    Validations.of(stack).acknowledge({ id: 'cdk-preflight::pf-ec2-sg-port-range', reason: 'known' });
    expect(() => app.synth()).not.toThrow();
  });

  test('observe mode is not gated', () => {
    const app = makeApp(cliHandlesReporting);
    Preflight.apply(app, { enforce: false });
    addBadSecurityGroup(new Stack(app, 'S'));
    expect(() => app.synth()).not.toThrow();
  });
});

describe('report formatting', () => {
  const reports = [{
    pluginName: 'cdk-preflight',
    conclusion: 'failure',
    violations: [{
      ruleName: 'pf-ec2-sg-port-range',
      description: 'port 99999 is out of range',
      severity: 'error',
      violatingConstructs: [{
        constructPath: 'MyStage/S/SG',
        constructFqn: 'aws-cdk-lib.aws_ec2.CfnSecurityGroup',
        cloudFormationResource: { logicalId: 'SG' },
      }],
    }],
  }];

  test('the borrowed CDK formatter is still resolvable', () => {
    // 解決できなくなったら fallbackFormat に落ちる。壊れたことに気づくための番人。
    expect(loadFormatter()).toBeDefined();
  });

  test('fallback formatting stays readable without the CDK formatter', () => {
    const out = fallbackFormat(reports);
    expect(out).toContain('port 99999 is out of range');
    expect(out).toContain('MyStage/S/SG');
    expect(out).toContain("Acknowledge with 'cdk-preflight::pf-ec2-sg-port-range'");
  });

  test('fallback formatting tolerates an empty report', () => {
    expect(fallbackFormat([])).toBe('');
  });
});

describe('metadata', () => {
  test('ruleIds returns all bundled rule ids', () => {
    const ids = Preflight.ruleIds();
    expect(ids.length).toBeGreaterThanOrEqual(9);
    expect(ids).toContain('pf-cloudfront-ttl-order');
    expect(new Set(ids).size).toBe(ids.length);
  });
});

describe('a rule pack that cannot run fails synthesis instead of passing silently', () => {
  // CDK はプラグインが throw すると conclusion: failure / violations: [] のレポートを
  // 書くだけで、CLI 経由ではそれが握り潰されて synth が緑のまま通る（issue #151）。
  // ルールが 1 本も走らなかったことは violation として立てる。
  const cliHandlesReporting = { '@aws-cdk/core:failSynthOnValidationErrors': false };

  /** 評価時に必ずエンジンを落とす rego（スカラーの `some .. in` は hard error）。 */
  const brokenRule: BundledRuleData = {
    id: 'pf-broken-for-test',
    service: 'test',
    severity: 'ERROR',
    title: 'deliberately broken',
    upstream: 'none',
    resourceTypes: [],
    rego: [
      'package cdk_preflight',
      '',
      'import rego.v1',
      '',
      'violation contains make_diag_full("pf-broken-for-test", "ERROR", "X", "(template)",',
      '\t"boom", "fix", "https://example.com") if {',
      '\tsome _ in true',
      '}',
      '',
    ].join('\n'),
  };

  function appWithBrokenRules(): App {
    const app = makeApp(cliHandlesReporting);
    Validations.of(app).addPlugins(new PreflightEnforcePlugin([brokenRule], false));
    installEnforceGate(app);
    return app;
  }

  let stderr: jest.SpyInstance;
  beforeEach(() => {
    stderr = jest.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => {
    stderr.mockRestore();
  });

  test('reports pf-engine-error with the engine message and stops synthesis', () => {
    const app = appWithBrokenRules();
    new sqs.CfnQueue(new Stack(app, 'S'), 'Q', {});
    expect(() => app.synth()).toThrow(/cdk-preflight: validation failed/);

    const violations = readReport(app);
    expect(violations.map((v) => v.ruleName)).toContain(ENGINE_ERROR_RULE);
    const engineError = violations.find((v) => v.ruleName === ENGINE_ERROR_RULE) as any;
    // エンジンは Error ではなく素の文字列を投げることがある。`undefined` に潰さない。
    expect(engineError.description).toMatch(/no preflight rule ran for it: .+/);
    expect(engineError.description).not.toMatch(/undefined/);
  });

  test('one unevaluatable template costs one template, not the whole run', () => {
    // QueueName を持つスタックだけでエンジンが落ちるルール。同じプラグインの
    // もう 1 枚（SG のスタック）では通常どおりルールが走ることを見る。
    const brokenForQueueNames: BundledRuleData = {
      ...brokenRule,
      id: 'pf-broken-for-queue-names',
      rego: [
        'package cdk_preflight',
        '',
        'import rego.v1',
        '',
        'violation contains make_diag_full("pf-broken-for-queue-names", "ERROR", name, "(template)",',
        '\t"boom", "fix", "https://example.com") if {',
        '\tsome name in resources_of_type("AWS::SQS::Queue")',
        '\tsome _ in resolve(name, "Properties.QueueName")',
        '}',
        '',
      ].join('\n'),
    };
    const sgRule = BUNDLED_RULES.find((r) => r.id === 'pf-ec2-sg-port-range')!;

    const app = makeApp(cliHandlesReporting);
    Validations.of(app).addPlugins(new PreflightEnforcePlugin([brokenForQueueNames, sgRule], false));
    installEnforceGate(app);
    new sqs.CfnQueue(new Stack(app, 'Broken'), 'Q', { queueName: 'q' });
    addBadSecurityGroup(new Stack(app, 'Good'));

    expect(() => app.synth()).toThrow(/cdk-preflight: validation failed/);
    const rules = readReport(app).map((v) => v.ruleName);
    expect(new Set(rules)).toEqual(new Set([ENGINE_ERROR_RULE, 'pf-ec2-sg-port-range']));
    expect(rules.filter((r) => r === ENGINE_ERROR_RULE)).toHaveLength(1);
  });
});

describe('resource-type pruning', () => {
  function writeTemplate(template: unknown): string {
    const file = path.join(tmpOut(), 'x.template.json');
    fs.writeFileSync(file, JSON.stringify(template));
    return file;
  }

  test('collects the types of every template', () => {
    const a = writeTemplate({ Resources: { Q: { Type: 'AWS::SQS::Queue' } } });
    const b = writeTemplate({ Resources: { T: { Type: 'AWS::SNS::Topic' } } });
    expect(templateResourceTypes([a, b])).toEqual(new Set(['AWS::SQS::Queue', 'AWS::SNS::Topic']));
  });

  test('keeps only the rules that name a type in the templates', () => {
    const rules: BundledRuleData[] = [
      { id: 'a', service: 's', severity: 'ERROR', title: 't', upstream: 'none', resourceTypes: ['AWS::SQS::Queue'], rego: '' },
      { id: 'b', service: 's', severity: 'ERROR', title: 't', upstream: 'none', resourceTypes: ['AWS::SNS::Topic'], rego: '' },
      // 複数タイプのルールは 1 つでも出てくれば残す（相手側が import されている構成のため）
      { id: 'c', service: 's', severity: 'ERROR', title: 't', upstream: 'none', resourceTypes: ['AWS::SNS::Topic', 'AWS::SQS::Queue'], rego: '' },
    ];
    const types = new Set(['AWS::SQS::Queue']);
    expect(prune(rules, types).map((r) => r.id)).toEqual(['a', 'c']);
  });

  test('keeps a rule that declares the "*" wildcard', () => {
    const anyResource: BundledRuleData = {
      id: 'a',
      service: 'tags',
      severity: 'ERROR',
      title: 't',
      upstream: 'none',
      resourceTypes: ['*'],
      rego: '',
    };
    expect(prune([anyResource], new Set(['AWS::SQS::Queue'])).map((r) => r.id)).toEqual(['a']);
  });

  // 以下は「刈り込みを諦める」ケース。判断材料が無いまま刈るとルールが黙って
  // 発火しなくなるので、全ルールを載せる側に倒す。
  test('gives up on a template it cannot read', () => {
    expect(templateResourceTypes([path.join(tmpOut(), 'missing.json')])).toBeUndefined();
  });

  test('gives up on a transformed template', () => {
    const file = writeTemplate({ Transform: 'AWS::Serverless-2016-10-31', Resources: {} });
    expect(templateResourceTypes([file])).toBeUndefined();
  });

  test('gives up when a resource type is not a static string', () => {
    const file = writeTemplate({ Resources: { 'Fn::ForEach::X': ['x', ['a'], {}] } });
    expect(templateResourceTypes([file])).toBeUndefined();
  });

  test('pruning off means every rule stays', () => {
    expect(prune(BUNDLED_RULES, undefined)).toHaveLength(BUNDLED_RULES.length);
  });

  test('a violation is still reported after pruning (end to end)', () => {
    const app = makeApp();
    Preflight.apply(app);
    addBadSecurityGroup(new Stack(app, 'S'));
    expect(() => app.synth()).toThrow(/pf-ec2-sg-port-range/);
  });
});

describe('service-level rule modules', () => {
  const rule = (id: string, service: string, rego: string): BundledRuleData => ({
    id, service, severity: 'ERROR', title: id, upstream: 'none', resourceTypes: [], rego,
  });
  const body = (id: string) => `package cdk_preflight\n\nimport rego.v1\n\n_pf_${id} := 1\n`;

  test('one module per service, with a single header', () => {
    const modules = mergeRuleModules([
      rule('a', 'sqs', body('a')),
      rule('b', 'sqs', body('b')),
      rule('c', 'logs', body('c')),
    ]);
    expect(modules.map((m) => m.name)).toEqual(['_pf_service_sqs', '_pf_service_logs']);
    const merged = modules[0].content;
    expect(merged.match(/^package /gm)).toHaveLength(1);
    expect(merged.match(/^import /gm)).toHaveLength(1);
    expect(merged).toContain('_pf_a := 1');
    expect(merged).toContain('_pf_b := 1');
  });

  test('only the header is stripped: an indented import-like line survives', () => {
    const [m] = mergeRuleModules([rule('a', 'sqs', 'package cdk_preflight\n\nimport rego.v1\n\n_pf_a := "\timport x"\n')]);
    expect(m.content).toContain('_pf_a := "\timport x"');
  });

  test('every bundled rule body survives the merge', () => {
    const merged = mergeRuleModules(BUNDLED_RULES).map((m) => m.content).join('\n');
    for (const r of BUNDLED_RULES) expect(merged).toContain(`"${r.id}"`);
  });
});

describe('fixed cost', () => {
  // 素直な CDK アプリ 1 スタックが吐くリソースタイプ。ルールパックの固定費はほぼ全部が
  // Rego のコンパイルで、コンパイル対象の本数にそのまま比例する（実測: 7 タイプに
  // 刈り込んだ 133 本で 1.3-1.6s、刈り込まず全 1918 本を載せると 12-15s）。
  const ORDINARY_APP_TYPES = new Set([
    'AWS::SQS::Queue',
    'AWS::IAM::Role',
    'AWS::IAM::Policy',
    'AWS::Lambda::Function',
    'AWS::Logs::LogGroup',
    'AWS::Logs::MetricFilter',
    'AWS::CloudWatch::Alarm',
  ]);

  // ルールは増え続ける前提のパックなので、壁時計ではなく「何本コンパイルするか」で縛る。
  // 刈り込みが壊れて全ルールが載るようになったら、ここが真っ先に落ちる。
  // 上限に当たったら、まず刈り込みが効いているかを疑うこと。上の 7 タイプにルールが
  // 正当に増えて当たったのなら、実測し直したうえで引き上げる。
  const MAX_SHARE = 0.15;

  test('an ordinary app compiles only a small share of the pack', () => {
    const kept = prune(BUNDLED_RULES, ORDINARY_APP_TYPES);
    // 0 本だとこのテストが素通りしてしまうので、刈り込みすぎの側も見る
    expect(kept.length).toBeGreaterThan(0);
    expect(kept.length / BUNDLED_RULES.length).toBeLessThan(MAX_SHARE);
  });
});
