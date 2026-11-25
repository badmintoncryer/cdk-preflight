/**
 * ルールの書き方の静的検査。「確信が持てないときは黙る」を書き手の記憶ではなく機械で守る。
 *
 * 誤検知の最大の原因は「省略された値を、ある値として読む」ことだった（#392 / #393 / #396 /
 * #402 / #403 / #405）。どれも AGENTS.md に罠として書かれていたのに、新しいルールで
 * 同じ形が書き直された。文章で覚えさせるのをやめ、危ない書き方そのものを落とす。
 *
 *   raw-to-number   to_number の直呼び。null を 0、真偽値を 0 / 1 にするので、省略や
 *                   AWS::NoValue が「0 が指定された」に化ける。rules/_lib/value.rego の
 *                   _pf_tonum / _pf_onum を使う。例外なし。
 *   inline-default  object.get の既定値に、サービスの値になりうるリテラルを書くこと
 *                   （"V1"、"GENEVE"、0、false、"" …）。省略を「その値が指定された」と
 *                   読む主張で、出典も実測も付かない。#403 は省略した PipelineType を "V1" と
 *                   読んでいた。既存の箇所は rules/_lint-baseline.txt に件数で載せ、増やせない
 *                   （減ったらファイルも減らす）。
 *
 * 使い方: npx ts-node --transpile-only --project test/tsconfig.json scripts/lint-rules.ts
 *         （test/structure.test.ts からも同じ関数を呼ぶ）
 */
import * as fs from 'fs';
import * as path from 'path';

export type LintCheck = 'raw-to-number' | 'inline-default';

export interface LintFinding {
  readonly check: LintCheck;
  /** rules/ からの相対パス */
  readonly file: string;
  readonly line: number;
  readonly text: string;
}

/** 既定値として書いてよいもの: 不在の番兵、null、メッセージ用の表示名、走査用の空コンテナ。 */
function isSafeDefault(arg: string): boolean {
  const a = arg.trim();
  if (a === 'null' || a === '[]' || a === '{}') return true;
  const s = /^"((?:[^"\\]|\\.)*)"$/.exec(a);
  if (s) {
    const v = s[1];
    // "__pf_absent" などの番兵と、"<unnamed>" / "(unset)" のような表示用の名前
    return v.startsWith('__pf') || /^[<(].*[>)]$/.test(v);
  }
  // 変数や式（v.index など）は既定値の主張ではない
  return !/^(-?\d+(\.\d+)?|true|false)$/.test(a);
}

/** コメントを空白に置き換える（文字列の中の # は残す）。行番号を保つ。 */
export function stripComments(src: string): string {
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

/** 文字列の中身を空白にする（呼び出し名の検索が文字列リテラルに反応しないように）。 */
function maskStrings(src: string): string {
  const out = [...src];
  let quote: string | null = null;
  for (let i = 0; i < out.length; i++) {
    const c = out[i];
    if (quote) {
      if (c === '\\' && quote === '"') {
        out[i] = ' ';
        if (i + 1 < out.length) out[++i] = ' ';
      } else if (c === quote) quote = null;
      else if (c !== '\n') out[i] = ' ';
      continue;
    }
    if (c === '"' || c === '`') quote = c;
  }
  return out.join('');
}

/** src[open] が '(' のとき、対応する ')' までのトップレベル引数を返す。 */
function callArgs(src: string, open: number): { args: string[]; end: number } | undefined {
  const args: string[] = [];
  let depth = 0;
  let quote: string | null = null;
  let start = open + 1;
  for (let i = open; i < src.length; i++) {
    const c = src[i];
    if (quote) {
      if (c === '\\' && quote === '"') i++;
      else if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === '`') quote = c;
    else if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') {
      depth--;
      if (depth === 0) {
        args.push(src.slice(start, i));
        return { args, end: i };
      }
    } else if (c === ',' && depth === 1) {
      args.push(src.slice(start, i));
      start = i + 1;
    }
  }
  return undefined;
}

const lineOf = (src: string, idx: number) => src.slice(0, idx).split('\n').length;

/** 1 ファイル分の検査。file は表示用の相対パス。 */
export function lintRego(file: string, rego: string): LintFinding[] {
  const src = stripComments(rego);
  const lines = rego.split('\n');
  const out: LintFinding[] = [];
  const isValueLib = file === path.join('_lib', 'value.rego');
  for (const m of maskStrings(src).matchAll(/(?<![A-Za-z0-9_.])to_number\(/g)) {
    if (isValueLib) continue;
    const line = lineOf(src, m.index!);
    out.push({ check: 'raw-to-number', file, line, text: lines[line - 1].trim() });
  }
  for (const m of src.matchAll(/(?<![A-Za-z0-9_])object\.get\(/g)) {
    const call = callArgs(src, m.index! + m[0].length - 1);
    if (!call || call.args.length !== 3) continue;
    if (isSafeDefault(call.args[2])) continue;
    const line = lineOf(src, m.index!);
    out.push({ check: 'inline-default', file, line, text: lines[line - 1].trim() });
  }
  return out;
}

/** rules/ 以下の全 .rego を検査する。 */
export function lintRules(rulesDir: string): LintFinding[] {
  const out: LintFinding[] = [];
  const walk = (dir: string): void => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.rego')) out.push(...lintRego(path.relative(rulesDir, p), fs.readFileSync(p, 'utf8')));
    }
  };
  walk(rulesDir);
  return out;
}

/** "<check> <file> <count>" の行を読む。 */
export function readBaseline(file: string): Map<string, number> {
  const out = new Map<string, number>();
  if (!fs.existsSync(file)) return out;
  for (const raw of fs.readFileSync(file, 'utf8').split('\n')) {
    const t = raw.trim();
    if (!t || t.startsWith('#')) continue;
    const [check, f, n] = t.split(/\s+/);
    out.set(`${check} ${f}`, Number(n));
  }
  return out;
}

export function countByFile(findings: LintFinding[]): Map<string, number> {
  const out = new Map<string, number>();
  for (const f of findings) out.set(`${f.check} ${f.file}`, (out.get(`${f.check} ${f.file}`) ?? 0) + 1);
  return out;
}

/**
 * ベースラインとの突き合わせ。raw-to-number は常に違反。inline-default は件数が
 * ベースラインを超えたら違反で、減ったのにベースラインが古いままでも違反（ラチェット）。
 */
export function baselineProblems(findings: LintFinding[], baseline: Map<string, number>): string[] {
  const problems: string[] = [];
  for (const f of findings.filter((x) => x.check === 'raw-to-number')) {
    problems.push(`${f.file}:${f.line}: to_number is not allowed in rules; use _pf_tonum(v) or _pf_onum(obj, key) from rules/_lib/value.rego (${f.text})`);
  }
  const counts = countByFile(findings.filter((x) => x.check === 'inline-default'));
  for (const [key, n] of counts) {
    const allowed = baseline.get(key) ?? 0;
    if (n > allowed) {
      const where = findings.filter((x) => `${x.check} ${x.file}` === key).map((x) => `  line ${x.line}: ${x.text}`).join('\n');
      problems.push(`${key}: ${n} inline object.get default(s), baseline allows ${allowed}. An omitted property must stay undefined; `
        + `if the service really fills in a default, write it down with its source instead of in object.get:\n${where}`);
    }
  }
  for (const [key, allowed] of baseline) {
    const n = counts.get(key) ?? 0;
    if (n < allowed) problems.push(`${key}: baseline says ${allowed} but there are ${n}; lower the line in rules/_lint-baseline.txt (or delete it at 0)`);
  }
  return problems;
}

export function renderBaseline(findings: LintFinding[]): string {
  const header = [
    '# scripts/lint-rules.ts のラチェット。既存の inline-default（object.get の既定値に書いた',
    '# サービスの値）の件数をファイルごとに凍結したもの。増やすとテストが落ち、減らしたら',
    '# この行も減らす。ここに載っている行は「省略をある値として読んでいる」見直し待ちの一覧。',
    '#',
    '# 書式: <check> <rules/ からの相対パス> <件数>',
    '',
  ];
  const rows = [...countByFile(findings.filter((f) => f.check === 'inline-default'))]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, n]) => `${k} ${n}`);
  return [...header, ...rows, ''].join('\n');
}

if (require.main === module) {
  const root = path.join(__dirname, '..', 'rules');
  const baselineFile = path.join(root, '_lint-baseline.txt');
  const findings = lintRules(root);
  if (process.argv.includes('--write-baseline')) {
    fs.writeFileSync(baselineFile, renderBaseline(findings));
    console.log(`wrote ${baselineFile}`);
  }
  const problems = baselineProblems(findings, readBaseline(baselineFile));
  for (const p of problems) console.log(p);
  const byCheck = countByFile(findings);
  const totals = new Map<string, number>();
  for (const [k, n] of byCheck) totals.set(k.split(' ')[0], (totals.get(k.split(' ')[0]) ?? 0) + n);
  console.log(`-- ${[...totals].map(([k, n]) => `${k}: ${n}`).join(', ') || 'no findings'}; ${problems.length} problem(s)`);
  process.exitCode = problems.length ? 1 : 0;
}
