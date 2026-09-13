/**
 * rules/<service>/<rule-id>/{rule.rego, meta.yaml, templates/{fail,pass}.template.json}
 * を検証し、src/rules.generated.ts と docs/rules.md を生成する。
 * 生成物はコミット対象。鮮度は test/structure.test.ts が担保する。
 */
import * as fs from 'fs';
import * as path from 'path';
import * as YAML from 'yaml';

interface Meta {
  id: string;
  service: string;
  resourceTypes: string[];
  severity: string;
  title: string;
  constraintSource: string;
  upstream: string;
  repro?: { method: string; evidence?: string };
  addedOn?: string;
  /** Region the fixture harness evaluates this rule's templates in (default us-east-1). */
  fixtureRegion?: string;
}

/** Shared helper module under rules/_lib/, loaded ahead of every rule (never emits diagnostics). */
export interface BundledLib {
  name: string;
  rego: string;
}

export interface BundledRule {
  id: string;
  service: string;
  severity: string;
  title: string;
  upstream: string;
  resourceTypes: string[];
  fixtureRegion?: string;
  rego: string;
}

const SEVERITIES = ['FATAL', 'ERROR', 'WARN', 'INFO'];
const UPSTREAMS = ['none', 'pending-engine', 'engine-pr', 'retired'];
const REPRO_METHODS = ['real-deploy', 'research-case', 'doc-only'];

const ISO_DATE = /\d{4}-\d{2}-\d{2}/;
const AWS_REGION = /\b(?:af|ap|ca|eu|il|me|sa|us)-[a-z]+-\d\b/;

/**
 * repro.evidence の最低要件。PR CI は実機デプロイを回さない（fork PR に自アカウントへの
 * 任意デプロイを許すことになるため）ので、real-deploy 宣言には bench 実測行そのもの
 * ——日付とリージョン——の貼り付けを機械的に要求して、口頭の「動作確認済み」を弾く。
 * 問題があればメッセージを返す。
 */
export function evidenceProblem(repro: { method: string; evidence?: string }): string | undefined {
  const ev = repro.evidence?.trim();
  if (!ev) return 'meta.repro.evidence is required';
  if (repro.method !== 'real-deploy') return undefined;
  if (!ISO_DATE.test(ev) || !AWS_REGION.test(ev)) {
    return 'meta.repro.method=real-deploy requires evidence quoting the bench run, with a YYYY-MM-DD date and a region (e.g. "bench 2026-09-03 ap-northeast-1: ... -> ROLLBACK_COMPLETE")';
  }
  return undefined;
}

/**
 * 実行時の severity は rego の `make_diag_full` 第 2 引数が持っており、`meta.yaml#severity`
 * はドキュメントにしか出ない。両者がずれると「表では WARN なのに synth が落ちる」に
 * なるので、ここで一致を強制する。複数の violation ブロックを持つルールは全部を見る。
 */
export function severityProblem(id: string, severity: string, rego: string): string | undefined {
  const emitted = new Set(
    [...rego.matchAll(/make_diag_full\(\s*"([^"]+)"\s*,\s*"([A-Z]+)"/g)]
      .filter((m) => m[1] === id)
      .map((m) => m[2]),
  );
  if (emitted.size === 0) return 'rule.rego must emit its own rule id through make_diag_full';
  const wrong = [...emitted].filter((s) => s !== severity);
  if (wrong.length === 0) return undefined;
  return `rule.rego emits ${wrong.sort().join('/')} but meta.severity is ${severity}; the runtime severity is the one in make_diag_full, so the two must agree`;
}

/**
 * `doc-only` は「デプロイが失敗するところを一度も見ていない」という意味なので、
 * synth を止める resolution にはしない。WARN ならレポートには載り、合成は通る。
 */
export function docOnlyProblem(repro: { method: string }, severity: string): string | undefined {
  if (repro.method !== 'doc-only' || severity === 'WARN') return undefined;
  return `meta.repro.method=doc-only requires severity WARN (got ${severity}); a constraint no deploy has been observed to reject must not fail synth`;
}

/**
 * enforce プラグインはルールを service ごとに 1 モジュールへ結合して読み込むので
 * （src/private/enforce.ts#mergeRuleModules）、結合時に落とせるヘッダ——
 * `package cdk_preflight` と `import rego.v1`——以外のものが混じっていてはいけない。
 * 別の import を書いたルールが黙って import 無しで結合されるのを防ぐ。
 */
/**
 * フィクスチャに現れうる「量」を 3 つのプールに集める。数値はテンプレートを生の文字列として
 * 走査するので、文字列に包まれた数（`"512"`）も拾う——rego 側が to_number で読む値がこれ。
 * 文字列長はエスケープを展開しないので `\n` は 2 文字と数える（境界ちょうどの値に
 * エスケープを混ぜないかぎり実害はない）。
 */
function fixturePools(raw: string) {
  const nums = new Set<number>([...raw.matchAll(/-?\d+(?:\.\d+)?/g)].map((m) => Number(m[0])));
  // JSON のエスケープを戻してから数える。rego の count(v) が見るのは解けた後の文字列なので、
  // 生のテキストのまま数えると TXT レコードのような `\"` を含む値でプールがずれる。
  const lens = new Set<number>([...raw.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => JSON.parse(`"${m[1]}"`).length));
  const sizes = new Set<number>();
  const walk = (v: unknown): void => {
    if (Array.isArray(v)) {
      sizes.add(v.length);
      v.forEach(walk);
    } else if (v && typeof v === 'object') {
      sizes.add(Object.keys(v).length);
      Object.values(v).forEach(walk);
    }
  };
  walk(JSON.parse(raw));
  return { nums, lens, sizes };
}

// count(...) の引数は 1 段だけ入れ子を許す。`count(split(v, \":\")) < 6` のような書き方は
// `[^)]*` だと最初の \")\" で止まって比較ごと取り逃がす（＝緩いペアが黙って通る）。
function stripRegoComments(src: string): string {
  const out = [...src];
  let quote: string | null = null;
  for (let i = 0; i < out.length; i++) {
    const c = out[i];
    if (quote) {
      if (c === '\\' && quote === '"') i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === '`') {
      quote = c;
      continue;
    }
    if (c === '#') {
      while (i < out.length && out[i] !== '\n') out[i++] = ' ';
    }
  }
  return out.join('');
}

const THRESHOLD = /(count\((?:[^()]|\([^()]*\))*\)|[A-Za-z_][A-Za-z0-9_.]*)\s*(<=|>=|<|>)\s*(-?\d+(?:\.\d+)?)/g;

/**
 * AGENTS.md 原則 2 の「両方のフィクスチャが境界に乗る」の機械チェック。rego のしきい値ごとに
 * 「違反する中で限界に最も近い値」が fail テンプレートに、「限界そのもの」が pass テンプレートに
 * 現れることを要求する。緩いペアはルールの向きしか証明しない（`count(v) < 20` は fail が
 * 5 文字なら定数が `< 10` でも鳴る）。
 *
 * 見るのは絶対値 2 以上の整数しきい値だけ。`count(x) > 0` や `n < 1` は存在チェックや
 * 空判定として書かれることが多く、そこを数えると検出のほとんどが偽陽性になる。
 * 小数のしきい値は「隣の値」が定義できないので対象外。
 * ヒューリスティックなので取り違えは残る（ARN を割った断片数のようなガードも拾う）:
 * 順序の無い制約として除外するものは rules/_boundary-exceptions.txt に理由付きで書く。
 */
export function boundaryProblem(rego: string, fail: string, pass: string): string | undefined {
  // 行コメントはロジックではない。`# x <= 23` と書いてあるだけの値をしきい値として
  // 要求してしまうので、走査の前に落とす。文字列の中の `#`（URL のフラグメント）を
  // 巻き込まないよう引用符の外だけを見て、長さは保って位置をずらさない。
  rego = stripRegoComments(rego);
  // `n := count(x)` と置いてから `n > 50` と書くのがこのリポジトリの標準形なので、代入を辿って
  // 「何を数えた値か」まで見る。数えた対象が配列なら要素数と、文字列なら長さと突き合わせる
  // ——どちらか決められないときだけ両方見る（偶然の一致を許すが、見当違いのプールで
  // 誤検出するよりましなので）。
  //
  // 代入はルール本体ごとに見る。1 つのモジュールの中で `n` が別の本体では別のものを
  // 指すのはふつうにあり、まとめて 1 つの表にすると片方が上書きされて見当違いの
  // プールと突き合わせてしまう（誤検出も見逃しも出る）。トップレベルの定義だけは
  // どの本体からも呼べるので全体で共有する。
  const blocks: string[] = [];
  let cur = '';
  let depth = 0;
  for (const line of rego.split('\n')) {
    cur += line + '\n';
    depth += (line.match(/\{/g) ?? []).length - (line.match(/\}/g) ?? []).length;
    if (depth <= 0 && line.trimEnd() === '}') {
      blocks.push(cur);
      cur = '';
      depth = 0;
    }
  }
  if (cur.trim()) blocks.push(cur);

  const ASSIGN = /([A-Za-z_][A-Za-z0-9_]*)(?:\([^)]*\))?\s*:=\s*(.*)/g;
  // `_pf_x_n(g, k) := count([...])` のようなトップレベル定義。呼び出しを本体まで辿るのに使う
  const shared = new Map([...rego.matchAll(/^([A-Za-z_][A-Za-z0-9_]*)(?:\([^)]*\))?\s*:=\s*(.*)/gm)].map((m) => [m[1], m[2]] as const));

  const ARRAYISH = /flatten_list\(|(?:^|[^A-Za-z0-9_)\]])\[|object\.keys\(|resources_of_type\(|\{[a-z]/;
  // object.get(x, "k", d) が返すものは d が教えてくれる: [] なら配列、"" なら文字列。
  // それ以外（"__pf_absent" のような番兵）は決められないので両方見る。
  const GET_ARRAY = /object\.get\([^()]*,\s*(?:\[\]|\{\})\s*\)/;
  const GET_STRING = /object\.get\([^()]*,\s*""\s*\)/;

  // `_pf_x_ok(v) if { n <= 100 }` を `not _pf_x_ok(...)` で使うのが、この直接比較と並ぶ
  // もう 1 つの標準形。守れている向きに書かれた比較なので、境界を出す前に裏返す。
  // そのままだと fail に 100、pass に 101 を要求してしまう（向きが逆）。
  const negated = new Set([...rego.matchAll(/\bnot\s+([A-Za-z_][A-Za-z0-9_]*)/g)].map((m) => m[1]));
  const FLIP: Record<string, string> = { '<': '>=', '<=': '>', '>': '<=', '>=': '<' };

  type Threshold = { counted: boolean; kind: 'array' | 'string' | 'both'; op: string; n: number };
  const thresholdsOf = (block: string): Threshold[] => {
    const assigned = new Map(shared);
    for (const m of block.matchAll(ASSIGN)) assigned.set(m[1], m[2]);
    const deref = (expr: string): string => {
      let e = expr.trim();
      for (let i = 0; i < 4; i++) {
        const call = /^([A-Za-z_][A-Za-z0-9_]*)\s*\(.*\)$/.exec(e);
        const body = call && assigned.get(call[1]);
        if (!body) return e;
        e = body.trim();
      }
      return e;
    };
    // `count(split(arn, ":")) >= 6` は ARN の形が壊れていないかのガードで、順序のある制約ではない。
    // 数えているのが split の結果なら、そのしきい値は境界の対象から外す。
    const kindOf = (expr: string): 'array' | 'string' | 'both' | 'shape' => {
      const inner = /^count\((.*)\)$/.exec(expr.trim())?.[1] ?? expr;
      const v = inner.trim();
      // rego が型を宣言していればそれが答え。`ev := resolve(...)` のあとに `is_object(ev)` と
      // 書いてあるなら、数えているのはマップの要素数であって文字列長ではない。resolve() は
      // 文字列も配列もマップも返すので、この宣言が無いときだけ下の推測に回す
      if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(v)) {
        if (new RegExp(`\\bis_string\\(${v}\\)`).test(block)) return 'string';
        if (new RegExp(`\\bis_(?:object|array)\\(${v}\\)`).test(block)) return 'array';
      }
      const src = deref(assigned.get(v) ?? inner);
      if (/\bsplit\(/.test(src)) return 'shape';
      if (GET_STRING.test(src)) return 'string';
      if (GET_ARRAY.test(src) || ARRAYISH.test(src)) return 'array';
      if (/resolve\(|json\.marshal\(|sprintf\(/.test(src)) return 'string';
      return 'both';
    };
    // 診断メッセージや修正案の文面にも `>= 31` のような比較が出てくる。文字列の中は
    // ロジックではないので、しきい値を探す前に落とす（長さを保って位置はずらさない）。
    const code = block.replace(/"(?:[^"\\\n]|\\.)*"|`[^`]*`/g, (m) => ' '.repeat(m.length));
    // どの定義の中の比較かは、その位置より前にある一番近い行頭の識別子で決まる。1 行の
    // 述語は閉じ括弧を持たないので次のブロックにくっついて切られる——ブロックの先頭では決められない。
    const owners = [...code.matchAll(/^([A-Za-z_][A-Za-z0-9_]*)/gm)].map((m) => [m.index ?? 0, m[1]] as const);
    const ownerAt = (i: number) => owners.filter(([at]) => at <= i).pop()?.[1] ?? '';
    return [...code.matchAll(THRESHOLD)]
      .map((m) => {
        const expr = m[1].startsWith('count(') ? m[1] : deref(assigned.get(m[1]) ?? '');
        const op = negated.has(ownerAt(m.index ?? 0)) ? FLIP[m[2]] : m[2];
        return { counted: expr.trimStart().startsWith('count('), kind: kindOf(expr), op, n: Number(m[3]) };
      })
      .filter((t): t is Threshold => t.kind !== 'shape' && Number.isInteger(t.n) && Math.abs(t.n) >= 2);
  };

  const thresholds = blocks.flatMap(thresholdsOf);
  if (thresholds.length === 0) return undefined;
  const pools = { fail: fixturePools(fail), pass: fixturePools(pass) };
  const problems: string[] = [];
  for (const t of thresholds) {
    // 違反する中で限界に最も近い値 / 限界そのもの
    const tightest = t.op === '<' ? t.n - 1 : t.op === '<=' ? t.n : t.op === '>' ? t.n + 1 : t.n;
    const limit = t.op === '<' ? t.n : t.op === '<=' ? t.n + 1 : t.op === '>' ? t.n : t.n - 1;
    const has = (p: ReturnType<typeof fixturePools>, v: number) => {
      if (!t.counted) return p.nums.has(v);
      if (t.kind === 'array') return p.sizes.has(v);
      if (t.kind === 'string') return p.lens.has(v);
      return p.lens.has(v) || p.sizes.has(v);
    };
    if (!has(pools.fail, tightest)) problems.push(`fail template has no ${tightest} for \`${t.op} ${t.n}\``);
    if (!has(pools.pass, limit)) problems.push(`pass template has no ${limit} for \`${t.op} ${t.n}\``);
  }
  return problems.length === 0 ? undefined : problems.join('; ');
}

export function headerProblem(rego: string): string | undefined {
  const packages = [...rego.matchAll(/^package\s+(\S+)/gm)].map((m) => m[1]);
  if (packages.length !== 1 || packages[0] !== 'cdk_preflight') {
    return `must declare exactly one "package cdk_preflight" (got ${packages.join(', ') || 'none'})`;
  }
  const imports = [...rego.matchAll(/^import\s+(\S+)/gm)].map((m) => m[1]);
  if (imports.length !== 1 || imports[0] !== 'rego.v1') {
    return `must declare exactly one "import rego.v1" and no other import (got ${imports.join(', ') || 'none'})`;
  }
  return undefined;
}

/** モジュールがトップレベルで定義している名前（`violation` は全ルールが積む集合なので除く）。 */
export function topLevelNames(rego: string): Set<string> {
  const names = new Set<string>();
  for (const m of rego.matchAll(/^(?:default\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:\(|:=|=[^=]|if\b|contains\b)/gm)) {
    if (m[1] !== 'violation') names.add(m[1]);
  }
  return names;
}

/**
 * ルール間のトップレベル名の衝突。
 *
 * ルールはすべて `package cdk_preflight` なので、別々のモジュールに書いても名前空間は
 * 1 つ——同名のヘルパーは「増分定義」として黙って合流する（同じ名前の完全規則が
 * 違う値を返せば、テンプレート次第で全ルールが評価エラーで死ぬ）。結合するかどうかに
 * 関わらず危険なので、ここで機械的に弾く。共有したい定義は rules/_lib/ へ置けばよい。
 */
export function nameCollisions(modules: { name: string; rego: string }[]): string[] {
  const owners = new Map<string, string[]>();
  for (const m of modules) {
    for (const n of topLevelNames(m.rego)) {
      owners.set(n, [...owners.get(n) ?? [], m.name]);
    }
  }
  return [...owners.entries()]
    .filter(([, os]) => os.length > 1)
    .map(([n, os]) => `${n} is defined by ${os.join(' and ')}; move it to rules/_lib/ instead`);
}

export function collectRules(root: string): BundledRule[] {
  const rulesDir = path.join(root, 'rules');
  const out: BundledRule[] = [];
  for (const service of fs.readdirSync(rulesDir).sort()) {
    const sdir = path.join(rulesDir, service);
    if (!fs.statSync(sdir).isDirectory() || service.startsWith('_')) continue;
    for (const id of fs.readdirSync(sdir).sort()) {
      const rdir = path.join(sdir, id);
      if (!fs.statSync(rdir).isDirectory()) continue;
      const regoPath = path.join(rdir, 'rule.rego');
      const metaPath = path.join(rdir, 'meta.yaml');
      if (!fs.existsSync(regoPath)) throw new Error(`${rdir}: missing rule.rego`);
      if (!fs.existsSync(metaPath)) throw new Error(`${rdir}: missing meta.yaml`);
      const rego = fs.readFileSync(regoPath, 'utf8');
      const meta = YAML.parse(fs.readFileSync(metaPath, 'utf8')) as Meta;
      for (const f of ['fail.template.json', 'pass.template.json']) {
        const p = path.join(rdir, 'templates', f);
        if (!fs.existsSync(p)) throw new Error(`${id}: missing templates/${f}`);
        JSON.parse(fs.readFileSync(p, 'utf8')); // must be valid JSON
      }
      if (meta.id !== id) throw new Error(`${rdir}: meta.id (${meta.id}) != directory name (${id})`);
      if (meta.service !== service) throw new Error(`${rdir}: meta.service (${meta.service}) != directory (${service})`);
      if (!SEVERITIES.includes(meta.severity)) throw new Error(`${id}: invalid severity ${meta.severity}`);
      if (!UPSTREAMS.includes(meta.upstream)) throw new Error(`${id}: invalid upstream ${meta.upstream}`);
      if (!meta.repro || !REPRO_METHODS.includes(meta.repro.method)) {
        throw new Error(`${id}: meta.repro.method must be one of ${REPRO_METHODS.join('/')}`);
      }
      const evProblem = evidenceProblem(meta.repro);
      if (evProblem) throw new Error(`${id}: ${evProblem}`);
      if (!meta.constraintSource) throw new Error(`${id}: meta.constraintSource (doc URL) is required`);
      if (!Array.isArray(meta.resourceTypes) || meta.resourceTypes.length === 0) {
        throw new Error(`${id}: meta.resourceTypes must be a non-empty list`);
      }
      if (!rego.includes(`"${id}"`)) throw new Error(`${id}: rule.rego must emit its own rule id`);
      const hdrProblem = headerProblem(rego);
      if (hdrProblem) throw new Error(`${id}: rule.rego ${hdrProblem}`);
      const sevProblem = severityProblem(id, meta.severity, rego);
      if (sevProblem) throw new Error(`${id}: ${sevProblem}`);
      const docProblem = docOnlyProblem(meta.repro, meta.severity);
      if (docProblem) throw new Error(`${id}: ${docProblem}`);
      out.push({
        id,
        service,
        severity: meta.severity,
        title: meta.title,
        upstream: meta.upstream,
        resourceTypes: meta.resourceTypes,
        ...(meta.fixtureRegion ? { fixtureRegion: meta.fixtureRegion } : {}),
        rego,
      });
    }
  }
  if (out.length === 0) throw new Error('no rules found under rules/');
  return out;
}

/** rules/_lib/*.rego: helpers shared by several rules. Retiring a rule never touches them. */
export function collectLibs(root: string): BundledLib[] {
  const dir = path.join(root, 'rules', '_lib');
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir).filter((f) => f.endsWith('.rego')).sort().map((f) => {
    const rego = fs.readFileSync(path.join(dir, f), 'utf8');
    const hdrProblem = headerProblem(rego);
    if (hdrProblem) throw new Error(`_lib/${f}: ${hdrProblem}`);
    if (rego.includes('violation contains')) throw new Error(`_lib/${f}: helper modules must not emit diagnostics`);
    return { name: `_lib/${f.replace(/\.rego$/, '')}`, rego };
  });
}

export function renderGenerated(rules: BundledRule[], libs: BundledLib[] = []): string {
  return [
    '// ~~ Generated by scripts/bundle-rules.ts from rules/**. Do not edit by hand.',
    '// ~~ Regenerate with: npx projen bundle-rules',
    '/* eslint-disable */',
    'export interface BundledRuleData {',
    '  readonly id: string;',
    '  readonly service: string;',
    '  readonly severity: string;',
    '  readonly title: string;',
    '  readonly upstream: string;',
    '  readonly resourceTypes: string[];',
    '  readonly fixtureRegion?: string;',
    '  readonly rego: string;',
    '}',
    '',
    `export const BUNDLED_RULES: BundledRuleData[] = ${JSON.stringify(rules, null, 2)};`,
    '',
    'export interface BundledLibData {',
    '  readonly name: string;',
    '  readonly rego: string;',
    '}',
    '',
    '/** Shared helper modules (rules/_lib). Always loaded before the rules. */',
    `export const BUNDLED_LIBS: BundledLibData[] = ${JSON.stringify(libs, null, 2)};`,
    '',
  ].join('\n');
}

export function renderDocs(rules: BundledRule[]): string {
  const rows = rules
    .map((r) => `| \`${r.id}\` | ${r.resourceTypes.join('<br>')} | ${r.title} | ${r.severity} | ${r.upstream} |`)
    .join('\n');
  return [
    '# Bundled rules',
    '',
    '<!-- Generated by scripts/bundle-rules.ts. Do not edit by hand. -->',
    '',
    '| Rule | Resource types | Constraint | Severity | Upstream status |',
    '|---|---|---|---|---|',
    rows,
    '',
  ].join('\n');
}

const SUPPORTED_START = '<!-- supported-resources:start -->';
const SUPPORTED_END = '<!-- supported-resources:end -->';

/**
 * README の「対応リソースタイプ」節。275 型あるので <details> で畳む。
 * AWS::<Service>::<Resource> の Service でまとめ、型ごとのルール数を添える。
 */
export function renderSupported(rules: BundledRule[]): string {
  const byService = new Map<string, Map<string, number>>();
  for (const rule of rules) {
    for (const type of rule.resourceTypes) {
      const parts = type.split('::');
      const [service, resource] = parts.length === 3 ? [parts[1], parts[2]] : ['(any resource type)', type];
      const types = byService.get(service) ?? new Map<string, number>();
      types.set(resource, (types.get(resource) ?? 0) + 1);
      byService.set(service, types);
    }
  }
  const services = [...byService.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  const typeCount = services.reduce((n, [, types]) => n + types.size, 0);
  const rows = services.map(([service, types]) => {
    const list = [...types.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([resource, count]) => `\`${resource}\` (${count})`)
      .join(', ');
    return `| **${service}** | ${list} |`;
  });
  return [
    SUPPORTED_START,
    '<details>',
    `<summary><b>${typeCount} resource types across ${services.length} services</b> — click to expand</summary>`,
    '',
    'Resource names are relative to `AWS::<Service>::`; the number in parentheses is how many rules target that type.',
    '',
    '| Service | Resource types |',
    '|---|---|',
    ...rows,
    '',
    '</details>',
    SUPPORTED_END,
  ].join('\n');
}

function withSupported(readme: string, rules: BundledRule[]): string {
  const start = readme.indexOf(SUPPORTED_START);
  const end = readme.indexOf(SUPPORTED_END);
  if (start < 0 || end < 0) {
    throw new Error(`README.md is missing the ${SUPPORTED_START} / ${SUPPORTED_END} markers`);
  }
  return readme.slice(0, start) + renderSupported(rules) + readme.slice(end + SUPPORTED_END.length);
}

if (require.main === module) {
  const root = path.join(__dirname, '..');
  const rules = collectRules(root);
  const libs = collectLibs(root);
  const collisions = nameCollisions([
    ...rules.map((r) => ({ name: r.id, rego: r.rego })),
    ...libs.map((l) => ({ name: l.name, rego: l.rego })),
  ]);
  if (collisions.length > 0) throw new Error(`rego name collisions:\n  ${collisions.join('\n  ')}`);
  fs.writeFileSync(path.join(root, 'src', 'rules.generated.ts'), renderGenerated(rules, libs));
  fs.mkdirSync(path.join(root, 'docs'), { recursive: true });
  fs.writeFileSync(path.join(root, 'docs', 'rules.md'), renderDocs(rules));
  const readme = path.join(root, 'README.md');
  fs.writeFileSync(readme, withSupported(fs.readFileSync(readme, 'utf8')
    .replace(/badge\/rules-\d+-/, `badge/rules-${rules.length}-`)
    .replace(/alt="\d+ bundled rules"/, `alt="${rules.length} bundled rules"`), rules));
  // eslint-disable-next-line no-console
  console.log(`bundled ${rules.length} rules -> src/rules.generated.ts, docs/rules.md, README.md`);
}
