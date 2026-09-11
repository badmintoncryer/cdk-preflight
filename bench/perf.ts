/**
 * enforce プラグインの固定費（ルールのコンパイル + 評価）を測る。
 *   npx ts-node bench/perf.ts [テンプレート枚数=3] [1 枚あたりのリソース束=10]
 *
 * NOPRUNE=1 を付けるとテンプレートに Transform を足して刈り込みを無効にする
 * （SAM / cloudformation-include と同じ状態＝全ルールをコンパイルする最悪ケース）。
 *
 * 1 プロセス 1 回のプラグイン呼び出し = 実際の synth 1 回ぶんに相当する。
 * 数値は WASM エンジンの状態に引きずられるので、比較は必ず別プロセスで取ること。
 */
import * as fs from 'fs';
import * as path from 'path';
import { PreflightEnforcePlugin } from '../src/private/enforce';
import { BUNDLED_RULES } from '../src/rules.generated';

const templates = Number(process.argv[2] ?? 3);
const bundles = Number(process.argv[3] ?? 10);
const outDir = path.join(__dirname, 'out', 'perf');

/** 素直な CDK アプリに出てくる形のテンプレート（7 リソースタイプ）。 */
function writeTemplate(index: number): string {
  const resources: Record<string, unknown> = {};
  for (let i = 0; i < bundles; i++) {
    resources[`Queue${i}`] = { Type: 'AWS::SQS::Queue', Properties: {} };
    resources[`Role${i}`] = {
      Type: 'AWS::IAM::Role',
      Properties: {
        AssumeRolePolicyDocument: {
          Version: '2012-10-17',
          Statement: [{
            Effect: 'Allow',
            Principal: { Service: 'lambda.amazonaws.com' },
            Action: 'sts:AssumeRole',
          }],
        },
      },
    };
    resources[`Policy${i}`] = {
      Type: 'AWS::IAM::Policy',
      Properties: {
        PolicyName: `p${i}`,
        Roles: [{ Ref: `Role${i}` }],
        PolicyDocument: {
          Version: '2012-10-17',
          Statement: [{
            Effect: 'Allow',
            Action: 'sqs:SendMessage',
            Resource: { 'Fn::GetAtt': [`Queue${i}`, 'Arn'] },
          }],
        },
      },
    };
    resources[`Fn${i}`] = {
      Type: 'AWS::Lambda::Function',
      Properties: {
        Runtime: 'nodejs22.x',
        Handler: 'index.handler',
        Role: { 'Fn::GetAtt': [`Role${i}`, 'Arn'] },
        Code: { ZipFile: 'exports.handler = async () => {};' },
      },
    };
    resources[`Lg${i}`] = { Type: 'AWS::Logs::LogGroup', Properties: {} };
    resources[`Filter${i}`] = {
      Type: 'AWS::Logs::MetricFilter',
      Properties: {
        LogGroupName: { Ref: `Lg${i}` },
        FilterPattern: '[time, level=ERROR, msg]',
        MetricTransformations: [{ MetricName: `E${i}`, MetricNamespace: 'Perf', MetricValue: '1' }],
      },
    };
    resources[`Alarm${i}`] = {
      Type: 'AWS::CloudWatch::Alarm',
      Properties: {
        Namespace: 'AWS/SQS',
        MetricName: 'ApproximateAgeOfOldestMessage',
        Period: 300,
        Statistic: 'Maximum',
        Threshold: 300,
        EvaluationPeriods: 1,
        ComparisonOperator: 'GreaterThanThreshold',
      },
    };
  }
  const file = path.join(outDir, `Perf${index}.template.json`);
  const transform = process.env.NOPRUNE === '1' ? { Transform: 'AWS::Serverless-2016-10-31' } : {};
  fs.writeFileSync(file, JSON.stringify({ ...transform, Resources: resources }));
  return file;
}

fs.mkdirSync(outDir, { recursive: true });
const stackTemplates = Array.from({ length: templates }, (_, i) => ({
  stackConstructPath: `App/Perf${i}`,
  templatePath: writeTemplate(i),
}));

const plugin = new PreflightEnforcePlugin(BUNDLED_RULES, false);
const t = Date.now();
const report = plugin.validate({
  stackTemplates,
  region: 'us-east-1',
  accountId: '123456789012',
} as any);
const elapsed = Date.now() - t;

// eslint-disable-next-line no-console
console.log(
  `rules=${BUNDLED_RULES.length} templates=${templates} resources/template=${bundles * 7} `
  + `prune=${process.env.NOPRUNE === '1' ? 'off' : 'on'} `
  + `validate=${elapsed}ms violations=${report.violations.length}`,
);

// エンジンを載せたプロセスは放っておくと終わらない（AGENTS.md「Known engine facts」）。
process.exit(0);
