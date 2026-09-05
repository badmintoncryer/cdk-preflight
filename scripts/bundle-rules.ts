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
      if (!rego.includes('import rego.v1')) throw new Error(`${id}: rule.rego must use "import rego.v1"`);
      out.push({
        id,
        service,
        severity: meta.severity,
        title: meta.title,
        upstream: meta.upstream,
        resourceTypes: meta.resourceTypes,
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
    if (!rego.includes('import rego.v1')) throw new Error(`_lib/${f}: must use "import rego.v1"`);
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
    .map((r) => `| \`${r.id}\` | ${r.resourceTypes.join('<br>')} | ${r.title} | ${r.upstream} |`)
    .join('\n');
  return [
    '# Bundled rules',
    '',
    '<!-- Generated by scripts/bundle-rules.ts. Do not edit by hand. -->',
    '',
    '| Rule | Resource types | Constraint | Upstream status |',
    '|---|---|---|---|',
    rows,
    '',
  ].join('\n');
}

if (require.main === module) {
  const root = path.join(__dirname, '..');
  const rules = collectRules(root);
  fs.writeFileSync(path.join(root, 'src', 'rules.generated.ts'), renderGenerated(rules, collectLibs(root)));
  fs.mkdirSync(path.join(root, 'docs'), { recursive: true });
  fs.writeFileSync(path.join(root, 'docs', 'rules.md'), renderDocs(rules));
  // eslint-disable-next-line no-console
  console.log(`bundled ${rules.length} rules -> src/rules.generated.ts, docs/rules.md`);
}
