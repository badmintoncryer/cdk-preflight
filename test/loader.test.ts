/**
 * ローダ（Preflight.apply）の CDK 統合テスト。
 * synth を実際に実行し、validation-report.json / 例外で検証する。
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { App, Stack, aws_ec2 as ec2, aws_logs as logs, aws_sqs as sqs } from 'aws-cdk-lib';
import { Preflight } from '../src';

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

describe('metadata', () => {
  test('ruleIds returns all bundled rule ids', () => {
    const ids = Preflight.ruleIds();
    expect(ids.length).toBeGreaterThanOrEqual(9);
    expect(ids).toContain('pf-cloudfront-ttl-order');
    expect(new Set(ids).size).toBe(ids.length);
  });
});
