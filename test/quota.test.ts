import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { App, CfnCondition, Fn, NestedStack, Stack, Validations, aws_ec2 as ec2, aws_lambda as lambda } from 'aws-cdk-lib';
import { PreflightQuotaPlugin } from '../src/private/enforce';
import { checkQuotas, flushQuotaCache, installQuotaCacheFlush, LAMBDA_CONCURRENCY_RULE, QUOTA_SKIPPED_RULE, type QuotaFacts, type QuotaRequest } from '../src/private/quota';

const ACCOUNT = '123456789012';

function facts(over: Partial<QuotaFacts> = {}): QuotaFacts {
  return {
    region: 'us-east-1',
    callerAccount: ACCOUNT,
    quotas: { vpc: 5, igw: 5, eip: 5 },
    usage: { vpc: 0, igw: 0, eip: 0, unreservedConcurrency: 1000 },
    templates: { S: null },
    ...over,
  };
}

/** スタック S を合成して、プラグインに渡るのと同じ形の context を作る。 */
function synth(build: (s: Stack) => void, env: { account?: string; region?: string } = { region: 'us-east-1' }) {
  const app = new App({ outdir: fs.mkdtempSync(path.join(os.tmpdir(), 'pf-quota-')) });
  build(new Stack(app, 'S', { env }));
  const asm = app.synth();
  return {
    stackTemplates: asm.stacks.map((s) => ({
      stackConstructPath: s.hierarchicalId,
      templatePath: s.templateFullPath,
      accountId: env.account,
      region: env.region,
    })),
  };
}

function run(ctx: ReturnType<typeof synth>, f: QuotaFacts | (() => QuotaFacts), extra: { now?: () => number } = {}) {
  const calls: QuotaRequest[] = [];
  const fetch = (req: QuotaRequest) => {
    calls.push(req);
    return typeof f === 'function' ? f() : f;
  };
  const violations = checkQuotas(ctx, { severity: 'error', ttlMs: 60_000, fetch, ...extra });
  flushQuotaCache();
  return { violations, calls, rules: violations.map((v) => v.ruleName) };
}

const vpcs = (n: number) => (s: Stack) => {
  for (let i = 0; i < n; i++) new ec2.CfnVPC(s, `V${i}`, { cidrBlock: `10.${i}.0.0/16` });
};

describe.each([
  ['vpc', 'pf-quota-vpcs-per-region', (s: Stack, i: number) => new ec2.CfnVPC(s, `R${i}`, { cidrBlock: '10.0.0.0/16' })],
  ['igw', 'pf-quota-internet-gateways-per-region', (s: Stack, i: number) => new ec2.CfnInternetGateway(s, `R${i}`)],
  ['eip', 'pf-quota-elastic-ips-per-region', (s: Stack, i: number) => new ec2.CfnEIP(s, `R${i}`)],
] as const)('%s quota', (key, rule, make) => {
  const ctx = (n: number) => synth((s) => { for (let i = 0; i < n; i++) make(s, i); });
  const usage = (used: number) => ({ ...facts().usage, [key]: used });

  test('used + new == quota passes', () => {
    expect(run(ctx(2), facts({ usage: usage(3) })).rules).not.toContain(rule);
  });

  test('used + new == quota + 1 fails', () => {
    const { violations } = run(ctx(3), facts({ usage: usage(3) }));
    const v = violations.find((x) => x.ruleName === rule)!;
    expect(v.severity).toBe('error');
    expect(v.violatingResources).toHaveLength(3);
  });

  test('the applied quota value counts, not the default', () => {
    expect(run(ctx(3), facts({ usage: usage(3), quotas: { vpc: 6, igw: 6, eip: 6 } })).rules).not.toContain(rule);
  });
});

describe('deployed state', () => {
  test('a resource already in the deployed stack is not counted again', () => {
    const ctx = synth(vpcs(2));
    const deployed = JSON.parse(fs.readFileSync(ctx.stackTemplates[0].templatePath, 'utf8'));
    // 5 個使用中のうち 2 個はこのスタックのもの。再デプロイで増えるのは 0
    expect(run(ctx, facts({ usage: { ...facts().usage, vpc: 5 }, templates: { S: deployed } })).rules).toEqual([]);
    // 同じ ctx だと 1 回目の結果がキャッシュから返るので、比較側は別に合成する
    expect(run(synth(vpcs(2)), facts({ usage: { ...facts().usage, vpc: 5 } })).rules).toEqual(['pf-quota-vpcs-per-region']);
  });

  test('a renamed logical id is a new resource (the old one is deleted after the create)', () => {
    const ctx = synth(vpcs(1));
    const deployed = { Resources: { Old: { Type: 'AWS::EC2::VPC' } } };
    expect(run(ctx, facts({ usage: { ...facts().usage, vpc: 5 }, templates: { S: deployed } })).rules).toEqual(['pf-quota-vpcs-per-region']);
  });

  test('an unparseable deployed template skips the stack instead of counting everything', () => {
    const { violations } = run(synth(vpcs(9)), facts({ templates: { S: 'unparseable' } }));
    expect(violations.map((v) => [v.ruleName, v.severity])).toEqual([[QUOTA_SKIPPED_RULE, 'warning']]);
  });
});

test('resources behind a Condition are not counted', () => {
  const ctx = synth((s) => {
    const c = new CfnCondition(s, 'C', { expression: Fn.conditionEquals('a', 'b') });
    for (let i = 0; i < 6; i++) new ec2.CfnVPC(s, `V${i}`, { cidrBlock: '10.0.0.0/16' }).cfnOptions.condition = c;
  });
  expect(run(ctx, facts()).rules).toEqual([]);
});

test('nested stacks are counted with their parent', () => {
  const ctx = synth((s) => {
    vpcs(3)(s);
    vpcs(3)(new NestedStack(s, 'N'));
  });
  const { violations, calls } = run(ctx, facts());
  expect(calls[0].stackNames).toEqual(['S']);
  expect(violations.map((v) => [v.ruleName, v.violatingResources.length])).toEqual([['pf-quota-vpcs-per-region', 6]]);
});

describe('lambda unreserved concurrency', () => {
  const fn = (reserved: number) => (s: Stack) => new lambda.CfnFunction(s, 'F', {
    role: `arn:aws:iam::${ACCOUNT}:role/r`,
    code: { zipFile: 'x' },
    runtime: 'nodejs22.x',
    handler: 'i.h',
    reservedConcurrentExecutions: reserved,
  });

  test('leaving exactly 100 unreserved passes', () => {
    expect(run(synth(fn(900)), facts()).rules).toEqual([]);
  });

  test('leaving 99 unreserved fails', () => {
    expect(run(synth(fn(901)), facts()).rules).toEqual([LAMBDA_CONCURRENCY_RULE]);
  });

  test('only the increase over the deployed value counts', () => {
    const deployed = { Resources: { F: { Type: 'AWS::Lambda::Function', Properties: { ReservedConcurrentExecutions: 800 } } } };
    // 未予約 200 のうち、増えるのは 100 だけ -> 残り 100
    const f = facts({ usage: { ...facts().usage, unreservedConcurrency: 200 }, templates: { S: deployed } });
    expect(run(synth(fn(900)), f).rules).toEqual([]);
    expect(run(synth(fn(901)), f).rules).toEqual([LAMBDA_CONCURRENCY_RULE]);
  });
});

describe('skipping', () => {
  test('a fetch failure is one warning and does not fail synth', () => {
    const { violations } = run(synth(vpcs(9)), () => {
      throw Object.assign(new Error('x'), { stderr: 'CredentialsProviderError: Could not load credentials' });
    });
    expect(violations).toHaveLength(1);
    expect(violations[0]).toMatchObject({ ruleName: QUOTA_SKIPPED_RULE, severity: 'warning' });
    expect(violations[0].description).toContain('Could not load credentials');
  });

  test('credentials for another account skip the stack', () => {
    const { violations } = run(synth(vpcs(9), { account: '210987654321', region: 'us-east-1' }), facts());
    expect(violations.map((v) => v.ruleName)).toEqual([QUOTA_SKIPPED_RULE]);
    expect(violations[0].description).toContain('AWS_PROFILE');
  });
});

test('exclude drops a quota finding', () => {
  const ctx = synth(vpcs(6));
  const violations = checkQuotas(ctx, { severity: 'error', ttlMs: 0, fetch: () => facts(), exclude: ['pf-quota-vpcs-per-region'] });
  expect(violations).toEqual([]);
});

test('a skipped stack is reported once, not once per nested stack', () => {
  const ctx = synth((s) => vpcs(1)(new NestedStack(s, 'N')), { account: '210987654321', region: 'us-east-1' });
  expect(run(ctx, facts()).rules).toEqual([QUOTA_SKIPPED_RULE]);
});

describe('cache', () => {
  test('reuses facts within the TTL, then refetches usage but not quotas', () => {
    const ctx = synth(vpcs(1));
    let t = 0;
    const now = () => t;
    expect(run(ctx, facts(), { now }).calls).toHaveLength(1);
    t = 59_999;
    expect(run(ctx, facts(), { now }).calls).toHaveLength(0);
    t = 60_000;
    const { calls, rules } = run(ctx, facts({ quotas: undefined, usage: { ...facts().usage, vpc: 5 } }), { now });
    expect(calls).toEqual([expect.objectContaining({ skipQuotas: true })]);
    // 取り直した使用量と、キャッシュのクォータで判定する
    expect(rules).toEqual(['pf-quota-vpcs-per-region']);
  });
});

test('refreshing an expired cache does not modify the cloud assembly during validation', () => {
  // CDK は検証プラグインの前後で cdk.out の既存ファイルを比べ、変わっていれば
  // IllegalPluginOperation で synth を落とす。TTL 切れの上書きを validate() 中にやるとこれに当たる
  const outdir = fs.mkdtempSync(path.join(os.tmpdir(), 'pf-quota-'));
  const synthOnce = () => {
    const app = new App({ outdir });
    vpcs(1)(new Stack(app, 'S', { env: { region: 'us-east-1' } }));
    Validations.of(app).addPlugins(new PreflightQuotaPlugin({ ttlMs: 0, fetch: () => facts() }));
    installQuotaCacheFlush(app);
    app.synth();
  };
  synthOnce();
  const cacheFile = path.join(outdir, '.cdk-preflight', 'quota-cache.json');
  const first = fs.readFileSync(cacheFile, 'utf8');
  expect(() => synthOnce()).not.toThrow();
  expect(fs.readFileSync(cacheFile, 'utf8')).not.toEqual(first);
});
