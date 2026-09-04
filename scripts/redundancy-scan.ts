/**
 * ルール不要化（redundancy）の検知。
 *
 * 各ルールの fail テンプレートを「素の」エンジン（カスタムルール無し）に掛け、
 * 組み込みが ERROR/FATAL を出すようになっていたら、そのルールはもう要らない。
 * aws-cdk-lib を上げた時にだけ状態が変わるので、判定は完全にローカル・無課金。
 *
 * jest の重複ガードは同じ条件でビルドを赤くするが、こちらは「どれを退役させるか」
 * の一覧を JSONL で吐き、月次レポート（bench/report.sh）が issue に載せる。
 * 出力: bench/out/redundancy.jsonl / 終了コードは常に 0（レポート専用）
 */
import * as fs from 'fs';
import * as path from 'path';
import { loadEngine } from '../src/private/enforce';
import { collectRules } from './bundle-rules';

interface Diagnostic {
  readonly ruleId: string;
  readonly severity: string;
  readonly source?: string;
  readonly message: string;
}

const root = path.join(__dirname, '..');
const engine = loadEngine();
if (!engine) {
  console.error('redundancy-scan: could not resolve @aws/cloudformation-validate');
  process.exit(0);
}

const bare = new engine.RegoEngine({});
const outDir = path.join(root, 'bench', 'out');
fs.mkdirSync(outDir, { recursive: true });
const outFile = path.join(outDir, 'redundancy.jsonl');
const lines: string[] = [];
const redundant: string[] = [];

for (const rule of collectRules(root)) {
  const fail = path.join(root, 'rules', rule.service, rule.id, 'templates', 'fail.template.json');
  const report = bare.validateDetailed(new engine.TemplateFile(fail), {});
  const blockers = ((report.diagnostics ?? []) as Diagnostic[]).filter(
    (d) => d.source !== 'CUSTOM' && (d.severity === 'ERROR' || d.severity === 'FATAL'),
  );
  if (blockers.length === 0) continue;
  redundant.push(rule.id);
  lines.push(JSON.stringify({
    rule: rule.id,
    service: rule.service,
    upstream: rule.upstream,
    engineRules: blockers.map((d) => d.ruleId),
    detail: blockers[0].message,
  }));
}

fs.writeFileSync(outFile, lines.length ? lines.join('\n') + '\n' : '');
const version = (() => {
  try {
    return require(require.resolve('aws-cdk-lib/package.json', { paths: [root] })).version as string;
  } catch {
    return 'unknown';
  }
})();

console.log(`redundancy-scan: aws-cdk-lib ${version} — ${redundant.length} of ${collectRules(root).length} rules are now covered by the bundled engine`);
for (const line of lines) {
  const r = JSON.parse(line);
  console.log(`  ${r.rule} (${r.service}) <- ${r.engineRules.join(',')}: ${r.detail}`);
}
if (redundant.length) {
  console.log('\nRetire them: rm -rf rules/<service>/<rule-id>/ && npx projen bundle-rules (see AGENTS.md "Rule lifecycle").');
}
