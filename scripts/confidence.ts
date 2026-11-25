/**
 * ルールの重大度を「書き手の宣言」ではなく「根拠の性質」から決める（②）と、手書きリストの台帳（④）。
 *
 * ERROR は synth を止める。止めてよいのは、テンプレートだけから違反と言い切れるときに限る。
 * 言い切れない根拠が 1 つでも混ざったルールは WARN にしかできない:
 *
 *   - 実機で落ちるところを見ていない（repro.method: doc-only。既存の docOnlyProblem）
 *   - テンプレートの外の状態を前提にしている（meta.assumes: [outside-template]）
 *     例: 別アカウントのレイヤー共有、コンソールで足した IdP（#412, #413）
 *   - AWS が値を足していく集合を、手書きの許可リストで閉じている（rules/_lists.yaml の
 *     kind: allow, growth: grows で refresh テストが無いもの）。今日の一覧に無い値は、明日には
 *     正しい値かもしれない（#238, #401: Origin Shield のリージョン漏れ）。
 *
 * リストは名前の参照をたどって推移的に効く（ルール -> _lib のヘルパー -> リスト）。
 */
import * as fs from 'fs';
import * as path from 'path';
import * as YAML from 'yaml';
import { stripComments } from './lint-rules';

export interface ListEntry {
  readonly file: string;
  readonly name: string;
  readonly kind: 'allow' | 'deny';
  readonly growth: 'grows' | 'stable';
  readonly refresh?: string;
  readonly source?: string;
}

const REGION = /"(?:us|eu|ap|sa|ca|me|af|il|mx|cn|us-gov)-[a-z]+-\d"/g;
const ACCOUNT = /"\d{12}"/g;

/** トップレベルの定義名 -> 本文。`name := ...` / `name(args) := ...` / `name if {` の形を拾う。 */
export function topLevelDefs(rego: string): Map<string, string> {
  const src = stripComments(rego);
  const out = new Map<string, string>();
  const starts = [...src.matchAll(/^([A-Za-z_][A-Za-z0-9_]*)\b/gm)]
    .filter((m) => !['package', 'import', 'violation', 'default'].includes(m[1]));
  const all = starts.map((m) => m.index!).concat([...src.matchAll(/^(?:package|import|violation|default)\b/gm)].map((m) => m.index!)).sort((a, b) => a - b);
  for (const m of starts) {
    const next = all.find((i) => i > m.index!) ?? src.length;
    out.set(m[1], (out.get(m[1]) ?? '') + src.slice(m.index!, next));
  }
  return out;
}

/** 台帳に載せるべきリスト: 8 件以上の文字列リテラル集合、またはリージョン / アカウント ID を 3 つ以上含む定義。 */
export function literalLists(rego: string): string[] {
  const out: string[] = [];
  for (const [name, body] of topLevelDefs(rego)) {
    const literalSet = new RegExp(`^${name}\\s*:=\\s*[\\[{]((?:\\s*"[^"]*"\\s*,?)+)\\s*[\\]}]`).exec(body);
    const big = literalSet && (literalSet[1].match(/"[^"]*"/g) ?? []).length >= 8;
    const ids = (body.match(REGION) ?? []).length >= 3 || (body.match(ACCOUNT) ?? []).length >= 3;
    if (big || ids) out.push(name);
  }
  return out;
}

export function readLists(file: string): ListEntry[] {
  return (YAML.parse(fs.readFileSync(file, 'utf8'))?.lists ?? []) as ListEntry[];
}

function regoFiles(rulesDir: string): { rel: string; rego: string }[] {
  const out: { rel: string; rego: string }[] = [];
  const walk = (dir: string): void => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.rego')) out.push({ rel: path.relative(rulesDir, p), rego: fs.readFileSync(p, 'utf8') });
    }
  };
  walk(rulesDir);
  return out;
}

/** 台帳と rules/ の突き合わせ。載っていないリストも、もう無い行も問題。 */
export function listRegistryProblems(rulesDir: string, entries: ListEntry[]): string[] {
  const problems: string[] = [];
  const found = new Set<string>();
  for (const { rel, rego } of regoFiles(rulesDir)) {
    for (const name of literalLists(rego)) {
      found.add(`${rel} ${name}`);
      if (!entries.some((e) => e.file === rel && e.name === name)) {
        problems.push(`${rel}: ${name} is a hand-written list; declare it in rules/_lists.yaml (kind allow|deny, growth grows|stable)`);
      }
    }
  }
  for (const e of entries) {
    if (!found.has(`${e.file} ${e.name}`)) problems.push(`rules/_lists.yaml: ${e.file} ${e.name} no longer exists; drop the entry`);
    if (!['allow', 'deny'].includes(e.kind)) problems.push(`rules/_lists.yaml: ${e.name}: kind must be allow or deny`);
    if (!['grows', 'stable'].includes(e.growth)) problems.push(`rules/_lists.yaml: ${e.name}: growth must be grows or stable`);
    if (e.refresh && !fs.existsSync(path.join(rulesDir, '..', e.refresh))) problems.push(`rules/_lists.yaml: ${e.name}: refresh ${e.refresh} does not exist`);
  }
  return problems;
}

/** 確信を下げるリスト = 閉じた世界を主張していて、AWS が増やす集合で、突き合わせテストが無いもの。 */
const weakens = (e: ListEntry) => e.kind === 'allow' && e.growth === 'grows' && !e.refresh;

/** 1 つの violation ブロック: どのルールの、どの重大度の指摘で、どの「確信を下げるリスト」に頼っているか。 */
export interface ViolationBlock {
  readonly id: string;
  readonly severity: string;
  readonly line: number;
  readonly weakLists: readonly string[];
}

/**
 * violation ブロックごとに、（_lib のヘルパーを通して）推移的に頼っている「確信を下げるリスト」を出す。
 * 名前の解決は全モジュール共通の 1 パッケージなので、ファイルをまたいで名前でたどる。
 * ブロック単位なのは、19 個の検査を持つルールのうち 1 個だけがリストに頼る、という形があるため
 * （pf-ssm-document-content）。そのブロックだけを WARN にすれば、残りは ERROR のまま止められる。
 */
export function violationBlocks(rulesDir: string, entries: ListEntry[]): ViolationBlock[] {
  const files = regoFiles(rulesDir);
  const defs = new Map<string, string>();
  for (const { rego } of files) for (const [n, b] of topLevelDefs(rego)) defs.set(n, (defs.get(n) ?? '') + b);
  const weak = new Set(entries.filter(weakens).map((e) => e.name));
  const refs = (body: string) => [...new Set(body.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? [])].filter((n) => defs.has(n));
  const memo = new Map<string, Set<string>>();
  const reach = (n: string, seen = new Set<string>()): Set<string> => {
    if (memo.has(n)) return memo.get(n)!;
    if (seen.has(n)) return new Set();
    seen.add(n);
    const out = new Set<string>(weak.has(n) ? [n] : []);
    for (const r of refs(defs.get(n) ?? '')) if (r !== n) for (const w of reach(r, seen)) out.add(w);
    memo.set(n, out);
    return out;
  };
  const out: ViolationBlock[] = [];
  for (const { rel, rego } of files) {
    if (!rel.endsWith('rule.rego')) continue;
    const src = stripComments(rego);
    const heads = [...src.matchAll(/^violation contains make_diag_full\(\s*"([^"]+)"\s*,\s*"([A-Z]+)"/gm)];
    const tops = [...src.matchAll(/^\S/gm)].map((m) => m.index!);
    for (const h of heads) {
      // ブロックの終わり = 次の列 0 の閉じ括弧の後ろにある、次のトップレベルの行
      const close = src.indexOf('\n}', h.index!);
      const end = tops.find((i) => i > (close < 0 ? h.index! : close + 2)) ?? src.length;
      const hit = new Set<string>();
      for (const r of refs(src.slice(h.index!, end))) for (const w of reach(r)) hit.add(w);
      out.push({ id: h[1], severity: h[2], line: src.slice(0, h.index!).split('\n').length, weakLists: [...hit].sort() });
    }
  }
  return out;
}

export interface RuleConfidenceInput {
  readonly id: string;
  readonly assumes?: readonly string[];
}

/**
 * 根拠から決まる上限。ERROR を名乗れるのは、確信を下げる根拠が何も無い指摘だけ。
 * meta.assumes はルール全体、リストはブロック単位で効く。
 */
export function confidenceProblems(rule: RuleConfidenceInput, blocks: readonly ViolationBlock[]): string[] {
  const out: string[] = [];
  for (const a of rule.assumes ?? []) {
    if (!(ASSUMES_VALUES as readonly string[]).includes(a)) out.push(`${rule.id}: unknown meta.assumes value '${a}' (known: ${ASSUMES_VALUES.join(', ')})`);
  }
  for (const b of blocks.filter((x) => x.id === rule.id && x.severity === 'ERROR')) {
    if (rule.assumes?.includes('outside-template')) {
      out.push(`${rule.id} (rule.rego:${b.line}) must emit WARN, not ERROR: meta.assumes says it depends on state outside the template`);
    } else if (b.weakLists.length) {
      out.push(`${rule.id} (rule.rego:${b.line}) must emit WARN, not ERROR: it closes a set AWS keeps growing with a hand-written allow-list `
        + `and no refresh test (${b.weakLists.join(', ')}; rules/_lists.yaml). Add a refresh test that checks the list against its source to keep ERROR.`);
    }
  }
  return out;
}

export const ASSUMES_VALUES = ['outside-template'] as const;

if (require.main === module) {
  const root = path.join(__dirname, '..', 'rules');
  const entries = readLists(path.join(root, '_lists.yaml'));
  for (const p of listRegistryProblems(root, entries)) console.log(p);
  for (const b of violationBlocks(root, entries)) if (b.weakLists.length) console.log(`${b.id}\t${b.line}\t${b.severity}\t${b.weakLists.join(',')}`);
}
