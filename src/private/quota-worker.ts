/**
 * クォータ検査の子プロセス。`quota.ts` が `execFileSync` で起動し、stdin で要求を受け、
 * stdout に JSON を 1 つ書いて終わる。validate() が同期なので、非同期の SDK 呼び出しは
 * ここに閉じ込める。SDK はこのファイルからしか読まないので、checkQuotas を使わない
 * 利用者の synth には読み込みのコストも乗らない。
 */
import * as fs from 'fs';
import { CloudFormationClient, DescribeStackResourceCommand, GetTemplateCommand } from '@aws-sdk/client-cloudformation';
import { DescribeAddressesCommand, EC2Client, paginateDescribeInternetGateways, paginateDescribeVpcs } from '@aws-sdk/client-ec2';
import { GetAccountSettingsCommand, LambdaClient } from '@aws-sdk/client-lambda';
import { GetAWSDefaultServiceQuotaCommand, GetServiceQuotaCommand, ServiceQuotasClient } from '@aws-sdk/client-service-quotas';
import { GetCallerIdentityCommand, STSClient } from '@aws-sdk/client-sts';
import type { QuotaFacts, QuotaRequest } from './quota';

/** 調整可能なクォータ（2026-10-16 `list-aws-default-service-quotas` で確認、既定値はどれも 5）。 */
const QUOTA_CODES = {
  vpc: ['vpc', 'L-F678F1CE'], // VPCs per Region
  igw: ['vpc', 'L-A4707A72'], // Internet gateways per Region
  eip: ['ec2', 'L-0263D0A3'], // EC2-VPC Elastic IPs
} as const;

async function main(): Promise<void> {
  const req: QuotaRequest = JSON.parse(fs.readFileSync(0, 'utf8'));
  const cfg = req.region ? { region: req.region } : {};
  const sts = new STSClient(cfg);
  const region = await sts.config.region();
  const ec2 = new EC2Client({ region });
  const cfn = new CloudFormationClient({ region });

  const [identity, vpc, igw, eip, lambda, quotas, templates] = await Promise.all([
    sts.send(new GetCallerIdentityCommand({})),
    count(paginateDescribeVpcs({ client: ec2 }, {}), (p) => p.Vpcs),
    count(paginateDescribeInternetGateways({ client: ec2 }, {}), (p) => p.InternetGateways),
    // DescribeAddresses はページングしない
    ec2.send(new DescribeAddressesCommand({ Filters: [{ Name: 'domain', Values: ['vpc'] }] })).then((r) => r.Addresses?.length ?? 0),
    new LambdaClient({ region }).send(new GetAccountSettingsCommand({})),
    req.skipQuotas ? Promise.resolve(undefined) : readQuotas(new ServiceQuotasClient({ region })),
    deployedTemplates(cfn, req.stackNames),
  ]);

  const facts: QuotaFacts = {
    region,
    callerAccount: identity.Account!,
    quotas,
    usage: { vpc, igw, eip, unreservedConcurrency: lambda.AccountLimit?.UnreservedConcurrentExecutions ?? 0 },
    templates,
  };
  process.stdout.write(JSON.stringify(facts));
}

async function count<P>(pages: AsyncIterable<P>, items: (p: P) => unknown[] | undefined): Promise<number> {
  let n = 0;
  for await (const p of pages) n += items(p)?.length ?? 0;
  return n;
}

async function readQuotas(sq: ServiceQuotasClient): Promise<QuotaFacts['quotas']> {
  const one = async ([ServiceCode, QuotaCode]: readonly [string, string]) => {
    try {
      return (await sq.send(new GetServiceQuotaCommand({ ServiceCode, QuotaCode }))).Quota!.Value!;
    } catch (e: any) {
      // 一度も引き上げていないアカウントには適用値が無い
      if (e?.name !== 'NoSuchResourceException') throw e;
      return (await sq.send(new GetAWSDefaultServiceQuotaCommand({ ServiceCode, QuotaCode }))).Quota!.Value!;
    }
  };
  const [vpc, igw, eip] = await Promise.all([one(QUOTA_CODES.vpc), one(QUOTA_CODES.igw), one(QUOTA_CODES.eip)]);
  return { vpc, igw, eip };
}

/**
 * デプロイ済みのテンプレートを `スタック名` と `スタック名/論理ID/...`（ネストしたスタック）の
 * キーで返す。スタックが無ければ null、JSON として読めなければ 'unparseable'。
 */
async function deployedTemplates(cfn: CloudFormationClient, stackNames: string[]): Promise<QuotaFacts['templates']> {
  const out: QuotaFacts['templates'] = {};
  const visit = async (key: string, stackName: string): Promise<void> => {
    let body: string | undefined;
    try {
      body = (await cfn.send(new GetTemplateCommand({ StackName: stackName, TemplateStage: 'Processed' }))).TemplateBody;
    } catch (e: any) {
      if (e?.name === 'ValidationError' && /does not exist/.test(String(e?.message))) {
        out[key] = null;
        return;
      }
      throw e;
    }
    let tpl: any;
    try {
      tpl = JSON.parse(body ?? '');
    } catch {
      out[key] = 'unparseable';
      return;
    }
    out[key] = tpl;
    const nested = Object.entries<any>(tpl.Resources ?? {}).filter(([, r]) => r?.Type === 'AWS::CloudFormation::Stack');
    await Promise.all(nested.map(async ([logicalId]) => {
      const res = await cfn.send(new DescribeStackResourceCommand({ StackName: stackName, LogicalResourceId: logicalId }));
      const physical = res.StackResourceDetail?.PhysicalResourceId;
      if (physical) await visit(`${key}/${logicalId}`, physical);
    }));
  };
  await Promise.all(stackNames.map((name) => visit(name, name)));
  return out;
}

main().catch((e) => {
  process.stderr.write(`${e?.name ?? 'Error'}: ${e?.message ?? String(e)}`);
  process.exit(1);
});
