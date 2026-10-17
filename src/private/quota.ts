import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { App, type IPolicyValidationContext, type PolicyViolation } from 'aws-cdk-lib';
import type { IConstruct } from 'constructs';

/**
 * Service Quotas 検査（`checkQuotas: true` のときだけ動く）。
 *
 * Rego のルールはテンプレート 1 枚しか見られず、アカウントの状態も知らない。ここでは
 * アプリ内の全スタック（ネストしたスタックを含む）が宛先のアカウント × リージョンに新しく作る
 * リソースを合計し、そのアカウントの適用済みクォータと現在の使用量に突き合わせる。
 * AWS への問い合わせは子プロセス（quota-worker.ts）に任せる。validate() が同期だから。
 */

type Resource = { Type?: string; Condition?: string; Properties?: Record<string, unknown>; Metadata?: Record<string, unknown> };
type Template = { Resources?: Record<string, Resource> };

export interface QuotaRequest {
  /** 未指定なら子プロセスが SDK の既定リージョンで補う */
  readonly region?: string;
  readonly stackNames: string[];
  /** キャッシュのクォータ値がまだ新しいときは取り直さない */
  readonly skipQuotas?: boolean;
}

export interface QuotaFacts {
  readonly region: string;
  readonly callerAccount: string;
  readonly quotas?: { vpc: number; igw: number; eip: number };
  readonly usage: { vpc: number; igw: number; eip: number; unreservedConcurrency: number };
  /** `スタック名` / `スタック名/論理ID`（ネスト）→ デプロイ済みテンプレート。無ければ null */
  readonly templates: Record<string, Template | null | 'unparseable'>;
}

export type QuotaFetcher = (req: QuotaRequest) => QuotaFacts;

export interface QuotaCheckOptions {
  /** 'error' なら synth を止める（enforce モード）、'warning' なら報告だけ */
  readonly severity: 'error' | 'warning';
  /** 使用量とデプロイ済みテンプレートのキャッシュ寿命 */
  readonly ttlMs: number;
  /** 報告しない id（Preflight.apply の exclude） */
  readonly exclude?: string[];
  /** テスト用。既定は子プロセスで AWS に問い合わせる */
  readonly fetch?: QuotaFetcher;
  readonly now?: () => number;
}

/** クォータの値そのものは滅多に変わらないので、使用量とは別に長めに持つ。 */
const QUOTA_TTL_MS = 24 * 60 * 60 * 1000;

/** Lambda は予約されていない同時実行がこれを下回る変更を拒む。 */
const MIN_UNRESERVED_CONCURRENCY = 100;

const COUNTED = {
  vpc: { type: 'AWS::EC2::VPC', rule: 'pf-quota-vpcs-per-region', name: 'VPCs per Region', code: 'vpc/L-F678F1CE' },
  igw: { type: 'AWS::EC2::InternetGateway', rule: 'pf-quota-internet-gateways-per-region', name: 'Internet gateways per Region', code: 'vpc/L-A4707A72' },
  eip: { type: 'AWS::EC2::EIP', rule: 'pf-quota-elastic-ips-per-region', name: 'EC2-VPC Elastic IPs', code: 'ec2/L-0263D0A3' },
} as const;
type Counted = keyof typeof COUNTED;

export const QUOTA_SKIPPED_RULE = 'pf-quota-check-skipped';
export const LAMBDA_CONCURRENCY_RULE = 'pf-quota-lambda-unreserved-concurrency';

/** `exclude` に書ける id。Rego のルールではないので BUNDLED_RULES には無い。 */
export const QUOTA_RULE_IDS: string[] = [...Object.values(COUNTED).map((q) => q.rule), LAMBDA_CONCURRENCY_RULE, QUOTA_SKIPPED_RULE];

export interface Demand {
  vpc: string[];
  igw: string[];
  eip: string[];
  /** 予約同時実行を増やす関数と、その増分 */
  concurrency: { id: string; delta: number }[];
}

/**
 * 1 枚のテンプレートが新しく使う分。デプロイ済みに同じ論理 ID・同じ型があれば既存として数えない。
 * 削除される分は差し引かない: CloudFormation が古いリソースを消すのは作成の後（cleanup）だから。
 */
export function demand(local: Template, deployed: Template | null | undefined): Demand {
  const d: Demand = { vpc: [], igw: [], eip: [], concurrency: [] };
  const old = deployed?.Resources ?? {};
  for (const [id, r] of Object.entries(local.Resources ?? {})) {
    // ponytail: Condition 付きは作られるか分からないので数えない（偽陰性側）。条件を評価するなら Fn::Equals 等の解決が要る
    if (!r || r.Condition) continue;
    const before = old[id]?.Type === r.Type ? old[id] : undefined;
    // ponytail: 置き換え（replacement）は新しい方を先に作るので一時的に 2 つになるが、数えない（偽陰性側）
    for (const k of Object.keys(COUNTED) as Counted[]) {
      if (r.Type === COUNTED[k].type && !before) d[k].push(id);
    }
    if (r.Type === 'AWS::Lambda::Function') {
      const now = r.Properties?.ReservedConcurrentExecutions;
      const was = before?.Properties?.ReservedConcurrentExecutions;
      // ponytail: デプロイ済みの値が組み込み関数なら 0 とみなすので、差分を多めに数える（偽陽性側）
      if (typeof now === 'number') {
        const delta = now - (typeof was === 'number' ? was : 0);
        if (delta > 0) d.concurrency.push({ id, delta });
      }
    }
  }
  return d;
}

interface Unit {
  /** facts.templates のキー */
  readonly key: string;
  readonly stackName: string;
  readonly stackConstructPath: string;
  readonly templatePath: string;
  readonly local: Template;
  readonly account?: string;
  readonly region?: string;
}

/** context のスタックと、そのネストしたスタック。context にはネストしたスタックが入らない。 */
export function collectUnits(context: Pick<IPolicyValidationContext, 'stackTemplates'>): Unit[] {
  const units: Unit[] = [];
  for (const st of context.stackTemplates) {
    const stackName = stackNameOf(st.templatePath);
    const base = {
      stackName,
      stackConstructPath: st.stackConstructPath,
      account: st.accountId ?? process.env.CDK_DEFAULT_ACCOUNT,
      region: st.region ?? process.env.CDK_DEFAULT_REGION,
    };
    const visit = (key: string, templatePath: string) => {
      const local: Template = JSON.parse(fs.readFileSync(templatePath, 'utf8'));
      units.push({ ...base, key, templatePath, local });
      for (const [id, r] of Object.entries(local.Resources ?? {})) {
        const child = r?.Type === 'AWS::CloudFormation::Stack' ? nestedTemplateFile(path.dirname(templatePath), r) : undefined;
        if (child) visit(`${key}/${id}`, path.join(path.dirname(templatePath), child));
      }
    };
    visit(stackName, st.templatePath);
  }
  return units;
}

/**
 * ネストしたスタックの子テンプレートの cdk.out 内のファイル名。`aws:asset:path` メタデータは
 * CLI 経由の synth にしか付かないので、無ければ TemplateURL の中のアセットハッシュを
 * `*.assets.json` で引く。
 */
function nestedTemplateFile(dir: string, r: Resource): string | undefined {
  const asset = r.Metadata?.['aws:asset:path'];
  if (typeof asset === 'string') return asset;
  const hash = /([0-9a-f]{64})\.json/.exec(JSON.stringify(r.Properties?.TemplateURL ?? ''))?.[1];
  if (!hash) return undefined;
  for (const f of fs.readdirSync(dir).filter((n) => n.endsWith('.assets.json'))) {
    const source = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')).files?.[hash]?.source?.path;
    if (typeof source === 'string') return source;
  }
  return undefined;
}

/** manifest.json からデプロイ時のスタック名を引く。見つからなければファイル名から。 */
function stackNameOf(templatePath: string): string {
  const file = path.basename(templatePath);
  try {
    const manifest = JSON.parse(fs.readFileSync(path.join(path.dirname(templatePath), 'manifest.json'), 'utf8'));
    for (const [id, a] of Object.entries<any>(manifest.artifacts ?? {})) {
      if (a?.type === 'aws:cloudformation:stack' && a.properties?.templateFile === file) {
        return a.properties.stackName ?? id;
      }
    }
  } catch {
    // fall through
  }
  return file.replace(/\.template\.json$/, '');
}

export function checkQuotas(context: Pick<IPolicyValidationContext, 'stackTemplates'>, opts: QuotaCheckOptions): PolicyViolation[] {
  return findViolations(context, opts).filter((v) => !opts.exclude?.includes(v.ruleName));
}

function findViolations(context: Pick<IPolicyValidationContext, 'stackTemplates'>, opts: QuotaCheckOptions): PolicyViolation[] {
  const violations: PolicyViolation[] = [];
  let units: Unit[];
  try {
    units = collectUnits(context);
  } catch (e) {
    return context.stackTemplates.length > 0
      ? [skipped(context.stackTemplates[0], `could not read the templates (${errorText(e)})`)]
      : [];
  }
  const byRegion = new Map<string | undefined, Unit[]>();
  for (const u of units) byRegion.set(u.region, [...(byRegion.get(u.region) ?? []), u]);

  for (const [region, group] of byRegion) {
    let facts: QuotaFacts;
    try {
      facts = cachedFetch(group[0].templatePath, { region, stackNames: [...new Set(group.map((u) => u.stackName))] }, opts);
    } catch (e) {
      violations.push(skipped(group[0], errorText(e)));
      continue;
    }
    const total: Demand = { vpc: [], igw: [], eip: [], concurrency: [] };
    const where = new Map<string, Unit>();
    const skippedStacks = new Set<string>();
    const skip = (u: Unit, why: string) => {
      // ネストしたスタックは親と同じ construct path に出るので、スタックごとに 1 件にする
      if (!skippedStacks.has(u.stackName)) violations.push(skipped(u, why));
      skippedStacks.add(u.stackName);
    };
    // 先にスタック単位で降りるかを決める。ネストの片方だけ数えると、半端な合計で判定してしまう
    for (const u of group) {
      if (u.account && /^\d{12}$/.test(u.account) && u.account !== facts.callerAccount) {
        skip(u, `the credentials belong to account ${facts.callerAccount}, but this stack deploys to ${u.account}. `
          + 'The CDK CLI does not pass --profile to the app; set AWS_PROFILE instead');
      } else if (facts.templates[u.key] === 'unparseable') {
        skip(u, `the deployed template of ${u.key} is not JSON`);
      }
    }
    for (const u of group) {
      if (skippedStacks.has(u.stackName)) continue;
      const d = demand(u.local, facts.templates[u.key] as Template | null | undefined);
      for (const k of Object.keys(COUNTED) as Counted[]) total[k].push(...d[k].map((id) => tag(where, u, id)));
      total.concurrency.push(...d.concurrency.map((c) => ({ id: tag(where, u, c.id), delta: c.delta })));
    }
    const env = `${facts.callerAccount}/${facts.region}`;
    for (const k of Object.keys(COUNTED) as Counted[]) {
      const quota = facts.quotas?.[k];
      const used = facts.usage[k];
      const adding = total[k].length;
      if (quota === undefined || adding === 0 || used + adding <= quota) continue;
      const q = COUNTED[k];
      violations.push({
        ruleName: q.rule,
        description: `This app creates ${adding} new ${q.type} in ${env}, which already uses ${used} of its `
          + `"${q.name}" quota of ${quota} (${q.code}); the deploy would fail once the quota is reached.`,
        severity: opts.severity,
        fix: `Request a quota increase in the Service Quotas console (${q.code}), or create fewer ${q.type} resources in this environment.`,
        violatingResources: total[k].map((tagged) => resourceOf(where, tagged)),
      });
    }
    const delta = total.concurrency.reduce((s, c) => s + c.delta, 0);
    const left = facts.usage.unreservedConcurrency - delta;
    if (delta > 0 && left < MIN_UNRESERVED_CONCURRENCY) {
      violations.push({
        ruleName: LAMBDA_CONCURRENCY_RULE,
        description: `This app reserves ${delta} more Lambda concurrent executions in ${env}, which has `
          + `${facts.usage.unreservedConcurrency} unreserved; Lambda rejects a change that leaves fewer than `
          + `${MIN_UNRESERVED_CONCURRENCY}.`,
        severity: opts.severity,
        fix: 'Lower ReservedConcurrentExecutions, or request a higher "Concurrent executions" quota (lambda/L-B99A9384).',
        violatingResources: total.concurrency.map((c) => resourceOf(where, c.id)),
      });
    }
  }
  return violations;
}

/** スタックをまたいで同じ論理 ID が出てくるので、キー付きの識別子にしてから出所を引く。 */
function tag(where: Map<string, Unit>, u: Unit, id: string): string {
  const t = `${u.key}\u0000${id}`;
  where.set(t, u);
  return t;
}

function resourceOf(where: Map<string, Unit>, tagged: string) {
  const u = where.get(tagged)!;
  return { resourceLogicalId: tagged.split('\u0000')[1], templatePath: u.templatePath, locations: ['(template)'] };
}

function skipped(st: { stackConstructPath: string; templatePath: string }, why: string): PolicyViolation {
  return {
    ruleName: QUOTA_SKIPPED_RULE,
    description: `cdk-preflight did not check service quotas for this stack: ${why}.`,
    severity: 'warning',
    fix: 'Make AWS credentials for the target account available to the app process (AWS_PROFILE or AWS_* environment variables), '
      + 'with servicequotas:GetServiceQuota, servicequotas:GetAWSDefaultServiceQuota, ec2:Describe{Vpcs,InternetGateways,Addresses}, lambda:GetAccountSettings, '
      + 'cloudformation:GetTemplate and cloudformation:DescribeStackResource.',
    violatingResources: [{ constructPath: st.stackConstructPath, templatePath: st.templatePath, locations: ['(template)'] }],
  };
}

function errorText(e: unknown): string {
  const stderr = (e as { stderr?: unknown })?.stderr;
  if (typeof stderr === 'string' && stderr.trim()) return stderr.trim();
  const message = (e as { message?: unknown })?.message;
  return typeof message === 'string' ? message : String(e);
}

interface CacheEntry {
  readonly at: number;
  readonly quotasAt: number;
  readonly facts: QuotaFacts;
}

/**
 * cdk.out/.cdk-preflight/quota-cache.json に置く。synth は diff/deploy/watch のたびに走るので、
 * 毎回 AWS に問い合わせないようにする。キーに AWS_PROFILE を入れ、資格情報を切り替えたら引き直す。
 */
function cachedFetch(templatePath: string, req: QuotaRequest, opts: QuotaCheckOptions): QuotaFacts {
  const now = (opts.now ?? Date.now)();
  const file = path.join(assemblyRoot(templatePath), '.cdk-preflight', 'quota-cache.json');
  const key = `${process.env.AWS_PROFILE ?? ''}|${req.region ?? ''}`;
  let cache: Record<string, CacheEntry> = {};
  try {
    cache = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    // 無い・壊れている
  }
  const hit = cache[key];
  const covers = hit && req.stackNames.every((n) => n in hit.facts.templates);
  if (hit && covers && now - hit.at < opts.ttlMs && hit.facts.quotas) return hit.facts;

  const quotasFresh = hit?.facts.quotas !== undefined && now - hit.quotasAt < QUOTA_TTL_MS;
  const got = (opts.fetch ?? fetchFromAws)({ ...req, skipQuotas: quotasFresh });
  const facts: QuotaFacts = { ...got, quotas: got.quotas ?? hit?.facts.quotas };
  cache[key] = { at: now, quotasAt: got.quotas ? now : hit!.quotasAt, facts };
  pendingCache.set(file, cache);
  return facts;
}

/**
 * validate() の最中は cdk.out に書けない。CDK は CloudFormationValidatePlugin 以外のプラグインの
 * 前後で cdk.out 配下の全ファイルのハッシュを取り、既存ファイルが変わっていれば
 * IllegalPluginOperation で synth を落とす（aws-cdk-lib 2.271.0 synthesis-validation）。
 * TTL 切れの上書きがちょうどそれに当たるので、書くのは synth が終わってからにする。
 */
const pendingCache = new Map<string, Record<string, CacheEntry>>();

export function flushQuotaCache(): void {
  for (const [file, cache] of pendingCache) {
    try {
      fs.mkdirSync(path.dirname(file), { recursive: true });
      fs.writeFileSync(file, JSON.stringify(cache));
    } catch {
      // キャッシュは無くても動く
    }
  }
  pendingCache.clear();
}

const FLUSH_INSTALLED = Symbol.for('cdk-preflight.quotaCacheFlush');

/** App.synth() の後で flushQuotaCache() を呼ぶようにする。 */
export function installQuotaCacheFlush(scope: IConstruct): void {
  const root = scope.node.root;
  if (!App.isApp(root)) return;
  const app = root as App & { [FLUSH_INSTALLED]?: boolean };
  if (app[FLUSH_INSTALLED]) return;
  Object.defineProperty(app, FLUSH_INSTALLED, { value: true, enumerable: false });
  const synth = app.synth.bind(app);
  app.synth = (options?: Parameters<App['synth']>[0]) => {
    try {
      return synth(options);
    } finally {
      flushQuotaCache();
    }
  };
}

/** Stage のスタックは cdk.out/assembly-*／に入るので、アプリの cdk.out まで上がる。 */
function assemblyRoot(templatePath: string): string {
  let dir = path.dirname(templatePath);
  while (path.basename(dir).startsWith('assembly-')) dir = path.dirname(dir);
  return dir;
}

function fetchFromAws(req: QuotaRequest): QuotaFacts {
  const worker = path.join(__dirname, 'quota-worker.js');
  if (!fs.existsSync(worker)) throw new Error(`quota worker not found at ${worker}`);
  const out = execFileSync(process.execPath, [worker], {
    input: JSON.stringify(req),
    encoding: 'utf8',
    timeout: 60_000,
    // デプロイ済みテンプレートの全文を返すので、既定の 1 MiB では大きいアプリほど黙って検査が外れる
    maxBuffer: 256 * 1024 * 1024,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  return JSON.parse(out);
}
