/**
 * ルール不要化（redundancy）の検知と記録。
 *
 * 各ルールの fail テンプレートを全ルール入りのエンジンに掛け、ルール自身の指摘がすべて組み込みの
 * ERROR/FATAL に覆われていたら（uncoveredFindings）、そのエンジン以上ではルールが要らない。
 * ただし peerDependency の下限の aws-cdk-lib を使う利用者にはまだ要るので、消さずに
 * meta.yaml#supersededBy に「どのエンジン版から要らないか」を記録する（AGENTS.md「Rule lifecycle」）。
 *
 *   redundancy-scan                 一覧だけ（月次レポート用）。exit は常に 0
 *   redundancy-scan --bisect        未記録の重複ごとに、npm のエンジン各版で最初に止めた版を探す
 *   redundancy-scan --bisect --write  その結果を meta.yaml に書き込む（upstream: retired + supersededBy）
 *
 * 出力: bench/out/redundancy.jsonl。kind は unrecorded（supersededBy を書くべき）、
 * partial（組み込みが fail テンプレートの一部のケースだけを止める＝そのケースを fail テンプレートから
 * 外す。ルールは残る）、deletable（下限の aws-cdk-lib が supersededBy.cdk に達した＝もう誰にも
 * 評価されない）。
 */
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { compareVersions, deployEnvironmentModule, engineVersion, loadEngine, mergeRuleModules } from '../src/private/enforce';
import { collectLibs, collectRules, type Finding, uncoveredFindings } from './bundle-rules';

interface Diagnostic extends Finding {
  readonly message: string;
}

const root = path.join(__dirname, '..');
const bisect = process.argv.includes('--bisect');
const write = process.argv.includes('--write');
const engine = loadEngine();
if (!engine) {
  console.error('redundancy-scan: could not resolve @aws/cloudformation-validate');
  process.exit(0);
}
const current = engineVersion() ?? 'unknown';
const floor = String(require(path.join(root, 'package.json')).peerDependencies['aws-cdk-lib']).replace(/^[\^~>=\s]+/, '');
const byVersion = (a: string, b: string) => compareVersions(a, b) ?? 0;

const outDir = path.join(root, 'bench', 'out');
fs.mkdirSync(outDir, { recursive: true });
const failTemplate = (r: { service: string; id: string }) =>
  path.join(root, 'rules', r.service, r.id, 'templates', 'fail.template.json');

const rules = collectRules(root);
const libs = collectLibs(root).map((l) => ({ name: l.name, content: l.rego }));
// 重複ガード（test/rule-table.ts）と同じく、リージョンごとに全ルールを載せた 1 エンジンで評価する。
const engines = new Map<string, any>();
function diagnose(rule: (typeof rules)[number]): Diagnostic[] {
  const region = rule.fixtureRegion ?? 'us-east-1';
  if (!engines.has(region)) {
    engines.set(region, new engine.RegoEngine({
      customRules: [...libs, ...mergeRuleModules(rules), deployEnvironmentModule(region, '123456789012')],
    }));
  }
  return (engines.get(region).validateDetailed(new engine.TemplateFile(failTemplate(rule)), {
    pseudoParameterOverrides: { accountId: '123456789012', region },
  }).diagnostics ?? []) as Diagnostic[];
}
const isBlocker = (d: Finding) => d.source !== 'CUSTOM' && (d.severity === 'ERROR' || d.severity === 'FATAL');

const unrecorded: { rule: (typeof rules)[number]; own: Finding[]; engineRules: string[]; detail: string }[] = [];
const partial: { rule: (typeof rules)[number]; uncovered: Finding[]; engineRules: string[]; detail: string }[] = [];
for (const rule of rules) {
  if (rule.supersededBy) continue; // 記録済みの一致は重複ガード（jest）の担当
  const ds = diagnose(rule);
  const blockers = ds.filter(isBlocker);
  if (blockers.length === 0) continue;
  const own = ds.filter((d) => d.source === 'CUSTOM' && d.ruleId === rule.id);
  const uncovered = uncoveredFindings(own, ds);
  const entry = { rule, engineRules: [...new Set(blockers.map((d) => d.ruleId))].sort(), detail: blockers[0].message };
  if (own.length > 0 && uncovered.length === 0) unrecorded.push({ ...entry, own });
  else partial.push({ ...entry, uncovered });
}
const deletable = rules.filter((r) => r.supersededBy && byVersion(floor, r.supersededBy.cdk) >= 0);

const lines = [
  ...unrecorded.map((u) => ({ kind: 'unrecorded', rule: u.rule.id, service: u.rule.service, upstream: u.rule.upstream, engineRules: u.engineRules, detail: u.detail })),
  ...partial.map((u) => ({ kind: 'partial', rule: u.rule.id, service: u.rule.service, upstream: u.rule.upstream, engineRules: u.engineRules, detail: u.detail })),
  ...deletable.map((r) => ({ kind: 'deletable', rule: r.id, service: r.service, upstream: r.upstream, engineRules: r.supersededBy!.engineRules, cdk: r.supersededBy!.cdk })),
].map((l) => JSON.stringify(l));
fs.writeFileSync(path.join(outDir, 'redundancy.jsonl'), lines.length ? lines.join('\n') + '\n' : '');

console.log(`redundancy-scan: engine ${current}, aws-cdk-lib floor ${floor} — ${unrecorded.length} unrecorded, `
  + `${partial.length} partial, ${deletable.length} deletable of ${rules.length} rules`);
for (const u of unrecorded) console.log(`  unrecorded ${u.rule.id} (${u.rule.service}) <- ${u.engineRules.join(',')}: ${u.detail}`);
for (const u of partial) {
  console.log(`  partial    ${u.rule.id} (${u.rule.service}) <- ${u.engineRules.join(',')}: ${u.detail}; still uncovered: `
    + u.uncovered.map((d) => `${d.entity?.logicalId}.${d.propertyPath}`).join(', '));
}
if (partial.length) console.log('\nPartial: move the cases the engine blocks out of the fail template; the rule stays.');
for (const r of deletable) console.log(`  deletable  ${r.id} (${r.service}): floor ${floor} >= ${r.supersededBy!.cdk}`);
if (unrecorded.length && !bisect) console.log('\nRecord them: npx projen redundancy-scan --bisect --write (see AGENTS.md "Rule lifecycle").');
if (deletable.length) console.log('\nDelete them: rm -rf rules/<service>/<rule-id>/ && npx projen bundle-rules.');

if (bisect && unrecorded.length) {
  // aws-cdk-lib（下限以上）ごとの同梱エンジン。supersededBy.cdk は「その版以上を最初に同梱した aws-cdk-lib」。
  const cdkEngines = (JSON.parse(execFileSync('npm', ['view', `aws-cdk-lib@>=${floor}`, 'version',
    'dependencies.@aws/cloudformation-validate', '--json'], { encoding: 'utf8' })) as Record<string, string>[])
    .map((o) => ({ cdk: o.version, engine: o['dependencies.@aws/cloudformation-validate'] }))
    .filter((o) => o.engine)
    .sort((a, b) => byVersion(a.cdk, b.cdk));
  const floorEngine = cdkEngines.find((o) => o.cdk === floor)?.engine;
  if (!floorEngine) throw new Error(`redundancy-scan: no engine found for aws-cdk-lib ${floor}`);
  // 下限のエンジンより新しく、今のエンジン以下の全版を 1 版 1 プロセスで評価する（WASM は 1 プロセス 1 エンジン）。
  const versions = (JSON.parse(execFileSync('npm', ['view', '@aws/cloudformation-validate', 'versions', '--json'],
    { encoding: 'utf8' })) as string[])
    .filter((v) => byVersion(v, floorEngine) > 0 && byVersion(v, current) <= 0)
    .sort(byVersion);
  const files = unrecorded.map((u) => failTemplate(u.rule));
  const blockersIn = new Map<string, Record<string, Finding[]>>(); // version -> template -> 組み込みの ERROR/FATAL
  for (const v of versions) {
    // リポジトリ内（bench/out 等）に展開すると jest の haste map が同名パッケージの重複で全滅する
    const dir = path.join(root, 'node_modules', '.cache', 'cdk-preflight-engines', v);
    if (!fs.existsSync(path.join(dir, 'package', 'package.json'))) {
      fs.mkdirSync(dir, { recursive: true });
      const tgz = execFileSync('npm', ['pack', `@aws/cloudformation-validate@${v}`, '--pack-destination', dir, '--silent'],
        { encoding: 'utf8' }).trim().split('\n').pop()!;
      execFileSync('tar', ['xzf', path.join(dir, tgz), '-C', dir]);
    }
    const out = execFileSync(process.execPath, ['-e', `
      const e = require(${JSON.stringify(path.join(dir, 'package'))});
      const inst = new e.RegoEngine({});
      // 1.10.0〜1.12.0 には validateDetailed が無い（validateTemplate に改名され、1.12.1 で非推奨の別名として復活）
      const validate = (inst.validateDetailed ?? inst.validateTemplate).bind(inst);
      const files = JSON.parse(require('fs').readFileSync(0, 'utf8'));
      const out = {};
      for (const f of files) {
        out[f] = (validate(new e.TemplateFile(f), {}).diagnostics ?? [])
          .filter((d) => d.source !== 'CUSTOM' && (d.severity === 'ERROR' || d.severity === 'FATAL'))
          .map((d) => ({ ruleId: d.ruleId, severity: d.severity, source: d.source, propertyPath: d.propertyPath,
            entity: { logicalId: d.entity && d.entity.logicalId } }));
      }
      require('fs').writeSync(1, JSON.stringify(out)); // パイプへの stdout.write は exit で 8KB に切れる
      process.exit(0);
    `], { input: JSON.stringify(files), encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
    blockersIn.set(v, JSON.parse(out));
    const covered = unrecorded.filter((u) => uncoveredFindings(u.own, blockersIn.get(v)![failTemplate(u.rule)]).length === 0);
    console.log(`  engine ${v}: covers ${covered.length}/${files.length}`);
  }
  for (const u of unrecorded) {
    const f = failTemplate(u.rule);
    // 最初に覆った版ではなく「そこから先ずっと覆っている」最初の版（途中で外れた版があれば後ろへ寄せる）。
    let first: string | undefined;
    for (const v of versions) {
      if (uncoveredFindings(u.own, blockersIn.get(v)![f]).length > 0) first = undefined;
      else if (first === undefined) first = v;
    }
    if (first === undefined) {
      console.log(`  ! ${u.rule.id}: the current engine blocks it but no published version between ${floorEngine} and ${current} does — skipped`);
      continue;
    }
    const cdk = cdkEngines.find((o) => byVersion(o.engine, first!) >= 0)?.cdk;
    if (!cdk) {
      console.log(`  ! ${u.rule.id}: no aws-cdk-lib release bundles engine >= ${first} — skipped`);
      continue;
    }
    console.log(`  ${u.rule.id}: engine ${first} (aws-cdk-lib ${cdk}) <- ${u.engineRules.join(',')}`);
    if (write) {
      const meta = path.join(root, 'rules', u.rule.service, u.rule.id, 'meta.yaml');
      const text = fs.readFileSync(meta, 'utf8');
      if (!/^upstream: .*$/m.test(text)) throw new Error(`${meta}: no upstream line`);
      fs.writeFileSync(meta, text.replace(/^upstream: .*$/m, [
        'upstream: retired',
        'supersededBy:',
        `  engine: ${first}`,
        `  cdk: ${cdk}`,
        `  engineRules: [${u.engineRules.join(', ')}]`,
      ].join('\n')));
    }
  }
}
