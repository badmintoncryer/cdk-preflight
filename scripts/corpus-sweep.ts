/**
 * 実テンプレート回帰（誤検知の根絶 7）: デプロイに成功したテンプレートの束に全ルールを掛ける。
 *
 * 誤検知はどれも、実際にデプロイされたアプリから見つかった（#392〜#413）。fail/pass の
 * 手書きテンプレートは書き手の想定の中しか通らないので、想定の外の形を大量に流す。
 * 束は aws-cdk の統合テストのスナップショット（integ-runner が実際にデプロイして
 * CREATE_COMPLETE を確かめてから書くもの、約 3,000 枚）。そこで鳴る自前ルールは、
 * そのテンプレートが本当に落ちる理由が無い限り誤検知。
 *
 * 環境は持たない（env-agnostic のスタックと同じ: deploy_region を焼かず、疑似パラメータも渡さない）。
 * Condition / Fn::If は enforce と同じく既定値で畳む。
 *
 *   npx ts-node --transpile-only --project test/tsconfig.json scripts/corpus-sweep.ts <dir-with-templates> [out.tsv]
 *   ... scripts/corpus-sweep.ts --check <aws-cdk の packages/>   （CI: rules/_corpus-accepted.txt と突き合わせる）
 *   bash scripts/fetch-corpus.sh <dir>                           （aws-cdk を CORPUS_REF で sparse clone する）
 *
 * 出力: <rule-id> <severity> <template（dir からの相対パス）> <logicalId> <message>
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { specializeTemplate } from '../src/private/conditions';
import { loadEngine, mergeRuleModules, validateTemplate } from '../src/private/enforce';
import { BUNDLED_LIBS, BUNDLED_RULES } from '../src/rules.generated';

export interface CorpusFinding {
  readonly rule: string;
  readonly severity: string;
  readonly template: string;
  readonly logicalId: string;
  readonly message: string;
}

function templatesUnder(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string): void => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith('.template.json')) out.push(p);
    }
  };
  walk(dir);
  return out.sort();
}

export function corpusFindings(dir: string, log: (s: string) => void = () => {}): CorpusFinding[] {
  const engine = loadEngine();
  const ids = new Set(BUNDLED_RULES.map((r) => r.id));
  const files = templatesUnder(dir);
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cdkpf-corpus-'));
  const out: CorpusFinding[] = [];
  // ルールが多いのでエンジンは 1 つを使い回し、テンプレート 500 枚ごとに作り直す（WASM のメモリ）
  let eng: any;
  files.forEach((file, i) => {
    if (i % 500 === 0) {
      eng?.free?.();
      eng = new engine.RegoEngine({ customRules: [...BUNDLED_LIBS.map((l) => ({ name: l.name, content: l.rego })), ...mergeRuleModules(BUNDLED_RULES)] });
      log(`${i}/${files.length}`);
    }
    let template: unknown;
    try {
      template = JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch {
      return;
    }
    if (!(template as any)?.Resources) return;
    const checked = path.join(tmp, 't.json');
    fs.writeFileSync(checked, JSON.stringify(specializeTemplate(template) ?? template));
    let ds: any[];
    try {
      ds = validateTemplate(eng, new engine.TemplateFile(checked), { disableBuiltinRules: true }).diagnostics ?? [];
    } catch (e) {
      log(`engine error on ${file}: ${e}`);
      return;
    }
    for (const d of ds) {
      if (d.source !== 'CUSTOM' || !ids.has(d.ruleId)) continue;
      out.push({
        rule: d.ruleId,
        severity: d.severity,
        template: path.relative(dir, file),
        logicalId: d.entity?.logicalId ?? '',
        message: String(d.message ?? '').replace(/\s+/g, ' '),
      });
    }
  });
  eng?.free?.();
  fs.rmSync(tmp, { recursive: true, force: true });
  return out;
}

export const ACCEPTED = path.join(__dirname, '..', 'rules', '_corpus-accepted.txt');

/** "<rule> <template> <logicalId>" の集合。 */
export function readAccepted(file = ACCEPTED): Set<string> {
  if (!fs.existsSync(file)) return new Set();
  return new Set(fs.readFileSync(file, 'utf8').split('\n').map((l) => l.replace(/#.*$/, '').trim()).filter(Boolean)
    .map((l) => l.split(/\s+/).slice(0, 3).join(' ')));
}

/** 受け入れていない指摘も、もう鳴らない受け入れ行も問題（ラチェット）。 */
export function corpusProblems(findings: CorpusFinding[], accepted: Set<string>): string[] {
  const found = new Map<string, CorpusFinding>();
  for (const f of findings) found.set(`${f.rule} ${f.template} ${f.logicalId}`, f);
  const problems: string[] = [];
  for (const [k, f] of found) {
    if (!accepted.has(k)) {
      problems.push(`${f.rule} fires on a template aws-cdk deployed (${f.template} ${f.logicalId}): ${f.message}\n`
        + '  If that template really deploys, the rule is a false positive: fix it. If it cannot deploy (placeholder values, '
        + 'a feature retired since), add the line to rules/_corpus-accepted.txt with the reason.');
    }
  }
  for (const a of accepted) if (!found.has(a)) problems.push(`rules/_corpus-accepted.txt: '${a}' no longer fires; delete the line`);
  return problems;
}

if (require.main === module && process.argv[2] === '--check') {
  const dir = process.argv[3];
  if (!dir) throw new Error('usage: corpus-sweep.ts --check <dir>');
  const problems = corpusProblems(corpusFindings(dir, (s) => console.error(s)), readAccepted());
  for (const p of problems) console.log(p);
  console.error(`-- ${problems.length} problem(s)`);
  process.exitCode = problems.length ? 1 : 0;
} else if (require.main === module) {
  const [dir, outFile] = process.argv.slice(2);
  if (!dir) throw new Error('usage: corpus-sweep.ts <dir> [out.tsv]');
  const findings = corpusFindings(dir, (s) => console.error(s));
  const rows = findings.map((f) => [f.rule, f.severity, f.template, f.logicalId, f.message].join('\t'));
  if (outFile) fs.writeFileSync(outFile, rows.join('\n') + '\n');
  else console.log(rows.join('\n'));
  const byRule = new Map<string, number>();
  for (const f of findings) byRule.set(f.rule, (byRule.get(f.rule) ?? 0) + 1);
  console.error(`-- ${findings.length} findings from ${byRule.size} rules`);
}
