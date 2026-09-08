/**
 * ルール探索・実装パイプラインのローカル判定を 1 プロセスにまとめたもの。
 *
 * エンジン（WASM）の初期化と rego のコンパイルが重いので、テンプレートを 1 枚ずつ
 * `ts-node -e` で回すと 1 件あたり数十秒かかり、往復ごとにヒアドキュメントを打ち直す
 * ぶんのトークンも乗る。ここに固定コマンドとして置いて、まとめて回してサマリ行だけ返す。
 *
 *   guard <path...>   素のエンジン（カスタムルール無し）に掛ける＝重複ガード。
 *                     ERROR/FATAL が出た候補はルールにしない。ディレクトリ可。
 *   check [rule-id | service ...]
 *                     rules/ を直接読み（bundle-rules もmeta 検証も通さない）1 エンジンに
 *                     全ルールを載せて fail/pass フィクスチャを判定する。meta.yaml の
 *                     evidence がまだ無い実装途中でも回せるのが `projen bundle-rules
 *                     && jest` との違い。仕上げの全緑確認は従来どおり jest 側の責務。
 *
 * 例: npx ts-node --transpile-only --project test/tsconfig.json scripts/rule-check.ts check iam
 */
import * as fs from 'fs';
import * as path from 'path';
import { deployEnvironmentModule, loadEngine } from '../src/private/enforce';

interface Diagnostic {
  readonly ruleId: string;
  readonly severity: string;
  readonly source?: string;
  readonly message?: string;
}

const ROOT = path.join(__dirname, '..');
const REGION = process.env.PF_REGION ?? 'us-east-1';
const ACCOUNT = process.env.PF_ACCOUNT ?? '123456789012';

const engine = loadEngine();
if (!engine) throw new Error('engine not resolvable (needs aws-cdk-lib >= 2.267.0)');

const blockers = (ds: Diagnostic[]) =>
  ds.filter((d) => d.source !== 'CUSTOM' && (d.severity === 'ERROR' || d.severity === 'FATAL'));

function evaluate(inst: any, file: string): Diagnostic[] {
  const report = inst.validateDetailed(new engine.TemplateFile(file), {
    pseudoParameterOverrides: { accountId: ACCOUNT, region: REGION },
  });
  return (report.diagnostics ?? []) as Diagnostic[];
}

function templates(paths: string[]): string[] {
  const out: string[] = [];
  for (const p of paths) {
    if (fs.statSync(p).isDirectory()) {
      out.push(...fs.readdirSync(p).filter((f) => f.endsWith('.json')).sort().map((f) => path.join(p, f)));
    } else {
      out.push(p);
    }
  }
  return out;
}

/** 素のエンジンに掛けて、止まる候補を落とす。 */
function guard(paths: string[]): number {
  // カスタムルールを 1 本も載せない＝素のエンジン（載せる場合は violation を定義する
  // モジュールが要る。deploy_environment だけ渡すと評価器がパッケージを解決できない）。
  const inst = new engine.RegoEngine({});
  let blocked = 0;
  for (const file of templates(paths)) {
    const b = blockers(evaluate(inst, file));
    if (b.length === 0) {
      console.log(`clean  ${path.basename(file)}`);
    } else {
      blocked++;
      console.log(`BLOCK  ${path.basename(file)}  ${b.map((d) => `${d.ruleId}/${d.severity}`).join(' ')}`);
    }
  }
  console.log(`-- ${templates(paths).length} templates, ${blocked} blocked by the bare engine (= drop these candidates)`);
  return 0;
}

interface RuleDir { id: string; service: string; dir: string; rego: string }

function collect(filters: string[]): RuleDir[] {
  const rulesDir = path.join(ROOT, 'rules');
  const out: RuleDir[] = [];
  for (const service of fs.readdirSync(rulesDir).sort()) {
    const sdir = path.join(rulesDir, service);
    if (service.startsWith('_') || !fs.statSync(sdir).isDirectory()) continue;
    for (const id of fs.readdirSync(sdir).sort()) {
      const dir = path.join(sdir, id);
      const rego = path.join(dir, 'rule.rego');
      if (!fs.existsSync(rego)) continue;
      out.push({ id, service, dir, rego: fs.readFileSync(rego, 'utf8') });
    }
  }
  if (filters.length === 0) return out;
  return out.filter((r) => filters.some((f) => r.id === f || r.service === f || r.id.includes(f)));
}

/**
 * fail が自分のルールで鳴るか / pass が全ルール無音か / どちらもエンジンに止められないか。
 * pass は「全ルール無音」でなければならないので、対象を絞っても全ルールを載せて評価する。
 */
function check(filters: string[]): number {
  const libs = fs.existsSync(path.join(ROOT, 'rules', '_lib'))
    ? fs.readdirSync(path.join(ROOT, 'rules', '_lib')).filter((f) => f.endsWith('.rego')).sort()
      .map((f) => ({ name: `_lib/${f.replace(/\.rego$/, '')}`, content: fs.readFileSync(path.join(ROOT, 'rules', '_lib', f), 'utf8') }))
    : [];
  const all = collect([]);
  const inst = new engine.RegoEngine({
    customRules: [...libs, ...all.map((r) => ({ name: r.id, content: r.rego })), deployEnvironmentModule(REGION, ACCOUNT)],
  });
  let bad = 0;
  for (const rule of collect(filters)) {
    const problems: string[] = [];
    for (const kind of ['fail', 'pass'] as const) {
      const file = path.join(rule.dir, 'templates', `${kind}.template.json`);
      if (!fs.existsSync(file)) { problems.push(`no ${kind} template`); continue; }
      const ds = evaluate(inst, file);
      const custom = ds.filter((d) => d.source === 'CUSTOM');
      const b = blockers(ds);
      if (b.length > 0) problems.push(`${kind}: engine ${b.map((d) => `${d.ruleId}/${d.severity}`).join(' ')}`);
      if (kind === 'fail' && !custom.some((d) => d.ruleId === rule.id)) problems.push('fail: own rule silent');
      if (kind === 'pass' && custom.length > 0) problems.push(`pass: ${[...new Set(custom.map((d) => d.ruleId))].join(' ')} fired`);
    }
    if (problems.length > 0) { bad++; console.log(`NG  ${rule.id}  ${problems.join('; ')}`); } else console.log(`ok  ${rule.id}`);
  }
  console.log(`-- ${collect(filters).length} rules checked (${all.length} loaded), ${bad} NG, region ${REGION}`);
  return bad === 0 ? 0 : 1;
}

const [mode, ...rest] = process.argv.slice(2);
if (mode === 'guard') {
  process.exitCode = guard(rest.length > 0 ? rest : ['.']);
} else if (mode === 'check') {
  process.exitCode = check(rest);
} else {
  console.error('usage: rule-check.ts guard <template.json|dir>... | rule-check.ts check [rule-id|service]...');
  process.exitCode = 2;
}
