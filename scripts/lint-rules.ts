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
 *                   読んでいた。例外なし。サービスが本当に既定値を埋めるなら、出典付きで
 *                   rules/_defaults.yaml に書き、`_pf_default("<owner>", "<key>")` で引く。
 *                   書かなければ省略は未定義のままで、ルールはその判定から降りる。
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

/**
 * 既定値が変数のとき、その変数が同じルール本体の中でリテラルに束縛されていれば、
 * リテラルを直接書いたのと同じ主張になる（`d := "V1"; object.get(x, "k", d)`）。
 * 呼び出しより前、直近のルール頭（行頭の識別子）までを探す。
 */
function boundToUnsafeLiteral(src: string, arg: string, at: number): boolean {
  const name = arg.trim();
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) return false;
  const before = src.slice(0, at);
  const heads = [...before.matchAll(/^[A-Za-z_]/gm)];
  const body = before.slice(heads.length ? heads[heads.length - 1].index! : 0);
  const re = new RegExp(`(?<![A-Za-z0-9_.])${name}\\s*:?=\\s*("(?:[^"\\\\]|\\\\.)*"|-?\\d+(?:\\.\\d+)?|true|false)(?![A-Za-z0-9_.])`, 'g');
  return [...body.matchAll(re)].some((b) => !isSafeDefault(b[1]));
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
    if (isSafeDefault(call.args[2]) && !boundToUnsafeLiteral(src, call.args[2], m.index!)) continue;
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

export function countByFile(findings: LintFinding[]): Map<string, number> {
  const out = new Map<string, number>();
  for (const f of findings) out.set(`${f.check} ${f.file}`, (out.get(`${f.check} ${f.file}`) ?? 0) + 1);
  return out;
}

/** 見つかったものはすべて違反（ベースラインは無い）。 */
export function lintProblems(findings: LintFinding[]): string[] {
  return findings.map((f) => f.check === 'raw-to-number'
    ? `${f.file}:${f.line}: to_number is not allowed in rules; use _pf_tonum(v) or _pf_onum(obj, key) from rules/_lib/value.rego (${f.text})`
    : `${f.file}:${f.line}: inline object.get default (${f.text}). An omitted property stays undefined, so the rule does not judge it. `
      + 'If the service really fills in a value, declare it with its source in rules/_defaults.yaml and read it with '
      + '_pf_default("<owner>", "<key>"); for a comparison that is false on omission use _pf_oval(obj, key); '
      + 'for an absence marker use a "__pf..." sentinel.');
}

if (require.main === module) {
  const root = path.join(__dirname, '..', 'rules');
  const findings = lintRules(root);
  const problems = lintProblems(findings);
  for (const p of problems) console.log(p);
  const byCheck = countByFile(findings);
  const totals = new Map<string, number>();
  for (const [k, n] of byCheck) totals.set(k.split(' ')[0], (totals.get(k.split(' ')[0]) ?? 0) + n);
  console.log(`-- ${[...totals].map(([k, n]) => `${k}: ${n}`).join(', ') || 'no findings'}; ${problems.length} problem(s)`);
  process.exitCode = problems.length ? 1 : 0;
}
