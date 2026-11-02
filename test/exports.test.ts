import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { App, CfnOutput, Fn, Stack, Stage, aws_sqs as sqs } from 'aws-cdk-lib';
import { Preflight } from '../src';
import { checkExports, EXPORT_CONFLICT_RULE, IMPORT_MISSING_RULE } from '../src/private/exports';

type Env = { account?: string; region?: string };

/** アプリを合成して、プラグインに渡るのと同じ形の context を作る。 */
function synth(build: (app: App) => Stack[]) {
  const app = new App({ outdir: fs.mkdtempSync(path.join(os.tmpdir(), 'pf-exports-')) });
  const stacks = build(app);
  app.synth();
  return {
    stackTemplates: stacks.map((s) => ({
      stackConstructPath: s.node.path,
      templatePath: path.join(s.node.scope instanceof Stage && !(s.node.scope instanceof App)
        ? (s.node.scope as Stage).outdir : app.outdir, s.templateFile),
      accountId: s.account,
      region: s.region,
    })),
  };
}

const ENV: Env = { account: '123456789012', region: 'us-east-1' };

function exporter(scope: App | Stage, id: string, env: Env, name: string) {
  const s = new Stack(scope, id, { env });
  new CfnOutput(s, 'Out', { value: 'x', exportName: name });
  return s;
}

describe(EXPORT_CONFLICT_RULE, () => {
  test('two stacks in one environment exporting the same name', () => {
    const ctx = synth((app) => [exporter(app, 'A', ENV, 'Shared'), exporter(app, 'B', ENV, 'Shared')]);
    const v = checkExports(ctx, { severity: 'warning' });
    expect(v.map((x) => x.ruleName)).toEqual([EXPORT_CONFLICT_RULE]);
    expect(v[0].description).toContain('Stacks A and B');
    expect(v[0].violatingResources[0].locations).toEqual(['Outputs/Out/Export/Name']);
  });

  test('the same name in two Regions or two accounts is fine', () => {
    const ctx = synth((app) => [
      exporter(app, 'A', ENV, 'Shared'),
      exporter(app, 'B', { ...ENV, region: 'eu-west-1' }, 'Shared'),
      exporter(app, 'C', { ...ENV, account: '210987654321' }, 'Shared'),
    ]);
    expect(checkExports(ctx, { severity: 'warning' })).toEqual([]);
  });

  test('Stages that deploy to the same environment conflict too', () => {
    const ctx = synth((app) => [exporter(new Stage(app, 'Dev'), 'A', ENV, 'Shared'), exporter(new Stage(app, 'Qa'), 'B', ENV, 'Shared')]);
    expect(checkExports(ctx, { severity: 'warning' }).map((x) => x.ruleName)).toEqual([EXPORT_CONFLICT_RULE]);
  });

  test('exclude', () => {
    const ctx = synth((app) => [exporter(app, 'A', ENV, 'Shared'), exporter(app, 'B', ENV, 'Shared')]);
    expect(checkExports(ctx, { severity: 'warning', exclude: [EXPORT_CONFLICT_RULE] })).toEqual([]);
  });
});

describe(IMPORT_MISSING_RULE, () => {
  const importer = (app: App, name: string) => {
    const s = new Stack(app, 'Consumer', { env: ENV });
    new sqs.CfnQueue(s, 'Q', { queueName: Fn.importValue(name) });
    return s;
  };

  test('an import named after a stack of the app that does not export it', () => {
    const ctx = synth((app) => [exporter(app, 'Producer', ENV, 'Producer:Other'), importer(app, 'Producer:QueueName')]);
    const v = checkExports(ctx, { severity: 'warning' });
    expect(v.map((x) => x.ruleName)).toEqual([IMPORT_MISSING_RULE]);
    expect(v[0].violatingResources[0].resourceLogicalId).toBe('Q');
  });

  test('exported, CDK-generated references, and names outside the app stay quiet', () => {
    const ctx = synth((app) => {
      const producer = new Stack(app, 'Producer', { env: ENV });
      const q = new sqs.Queue(producer, 'Queue');
      const consumer = new Stack(app, 'Consumer', { env: ENV });
      new sqs.CfnQueue(consumer, 'Q1', { queueName: q.queueName }); // CDK creates the export
      new sqs.CfnQueue(consumer, 'Q2', { queueName: Fn.importValue('SomeOtherApp:Name') });
      new sqs.CfnQueue(consumer, 'Q3', { queueName: Fn.importValue('no-colon') });
      return [producer, consumer];
    });
    expect(checkExports(ctx, { severity: 'warning' })).toEqual([]);
  });

  test('a stack of the same name in another Region does not count', () => {
    const ctx = synth((app) => [exporter(app, 'Producer', { ...ENV, region: 'eu-west-1' }, 'Producer:QueueName'), importer(app, 'Producer:QueueName')]);
    // 名前は Producer だが eu-west-1。us-east-1 の Consumer から見ると、アプリ内のスタックではない
    expect(checkExports(ctx, { severity: 'warning' })).toEqual([]);
  });
});

test('Preflight.apply reports them as warnings and synth goes on', () => {
  const app = new App({ outdir: fs.mkdtempSync(path.join(os.tmpdir(), 'pf-exports-')) });
  exporter(app, 'A', ENV, 'Shared');
  exporter(app, 'B', ENV, 'Shared');
  Preflight.apply(app);
  const asm = app.synth();
  const report = JSON.parse(fs.readFileSync(path.join(asm.directory, 'validation-report.json'), 'utf8'));
  const ours = report.pluginReports.find((r: any) => r.pluginName === 'cdk-preflight-exports');
  expect(ours.conclusion).toBe('success');
  expect(ours.violations.map((v: any) => v.ruleName)).toEqual([EXPORT_CONFLICT_RULE]);
});

test('exclude accepts the export rule ids', () => {
  const app = new App();
  expect(() => Preflight.apply(app, { exclude: [EXPORT_CONFLICT_RULE, IMPORT_MISSING_RULE] })).not.toThrow();
});
