/**
 * ③ 反証工程の機械部分: 「省略したら落ちる」という主張をルールが黙って持っていないかを探す。
 *
 * 各ルールの pass テンプレート（実機で CREATE_COMPLETE を確かめた形）から、ルールが見るリソース型の
 * プロパティを 1 つずつ抜いた変異体を作り、エンジンに掛ける。抜いたことでそのルールが鳴り、
 * しかもエンジン組み込みの ERROR/FATAL（スキーマの必須違反など）は出ない変異体は、
 * 「このプロパティを省略するとデプロイが落ちる」というルールの主張そのもの。
 * 省略値の読み違え（#392〜#405）はすべてこの形をしていた。
 *
 * 見つかった主張は meta.yaml#omissionFails に、実測の証拠付きで書いて初めて許される
 * 既存の主張は rules/_omission-baseline.txt に凍結（ラチェット）。test/omission.test.ts が全ルールを回す（約 6 分）。
 *
 *   npx ts-node --transpile-only --project test/tsconfig.json scripts/omission-sweep.ts [rule-id|service ...]
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as YAML from 'yaml';
import { deployEnvironmentModule, loadEngine, mergeRuleModules, validateTemplate } from '../src/private/enforce';
import { BUNDLED_LIBS, BUNDLED_RULES } from '../src/rules.generated';

interface Diagnostic { ruleId: string; severity: string; source?: string; entity?: { logicalId?: string }; propertyPath?: string }

const ROOT = path.join(__dirname, '..');
const engine = loadEngine();

/** プロパティのパス（"A", "A.B", "A.0.B"）を深さ 3 まで列挙する。配列は先頭要素だけ見る。 */
export function propertyPaths(props: unknown, depth = 3, prefix = ''): string[] {
  if (!props || typeof props !== 'object' || depth === 0) return [];
  const out: string[] = [];
  if (Array.isArray(props)) {
    if (props.length > 0 && props[0] && typeof props[0] === 'object') out.push(...propertyPaths(props[0], depth, `${prefix}0.`));
    return out;
  }
  for (const [k, v] of Object.entries(props as Record<string, unknown>)) {
    if (k.startsWith('Fn::') || k === 'Ref') continue;
    out.push(`${prefix}${k}`);
    out.push(...propertyPaths(v, depth - 1, `${prefix}${k}.`));
  }
  return out;
}

/** props から path を抜いた深いコピー。 */
export function without(props: any, p: string): any {
  const copy = JSON.parse(JSON.stringify(props));
  const segs = p.split('.');
  let cur = copy;
  for (const s of segs.slice(0, -1)) cur = cur?.[s];
  if (cur && typeof cur === 'object') delete cur[segs[segs.length - 1]];
  return copy;
}

export interface OmissionClaim { readonly rule: string; readonly key: string }

/** "Properties" 内のパスを、配列の添字をワイルドカードにしたキー（"AWS::X::Y.A.*.B"）にする。 */
export const claimKey = (type: string, p: string) => `${type}.${p.split('.').map((s) => (/^\d+$/.test(s) ? '*' : s)).join('.')}`;

/**
 * 省略したらルールが鳴る（＝「省略すると落ちる」と主張している）プロパティを全部出す。
 * meta.omissionFails に書いてあるものも含めて返す（突き合わせは呼び出し側）。
 */
export function omissionClaims(filters: string[] = [], onClaim?: (c: OmissionClaim, mutant: unknown) => void): OmissionClaim[] {
  const rules = BUNDLED_RULES.filter((r) => !filters.length || filters.some((f) => r.id === f || r.service === f));
  const services = [...new Set(rules.map((r) => r.service))];
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cdkpf-omit-'));
  const file = path.join(tmp, 'm.json');
  const out = new Map<string, OmissionClaim>();
  for (const service of services) {
    const svcRules = BUNDLED_RULES.filter((r) => r.service === service);
    const engines = new Map<string, any>();
    const engineFor = (region: string) => {
      if (!engines.has(region)) {
        engines.set(region, new engine.RegoEngine({
          customRules: [...BUNDLED_LIBS.map((l) => ({ name: l.name, content: l.rego })), ...mergeRuleModules(svcRules), deployEnvironmentModule(region, '123456789012')],
        }));
      }
      return engines.get(region);
    };
    for (const rule of rules.filter((r) => r.service === service)) {
      const region = rule.fixtureRegion ?? 'us-east-1';
      const dir = path.join(ROOT, 'rules', service, rule.id);
      const pass = JSON.parse(fs.readFileSync(path.join(dir, 'templates', 'pass.template.json'), 'utf8'));
      for (const [lid, res] of Object.entries<any>(pass.Resources ?? {})) {
        if (!rule.resourceTypes.includes(res.Type) || !res.Properties) continue;
        for (const p of propertyPaths(res.Properties)) {
          const key = claimKey(res.Type, p);
          if (out.has(`${rule.id} ${key}`)) continue;
          const mutant = { ...pass, Resources: { ...pass.Resources, [lid]: { ...res, Properties: without(res.Properties, p) } } };
          fs.writeFileSync(file, JSON.stringify(mutant));
          const ds = (validateTemplate(engineFor(region), new engine.TemplateFile(file), {
            pseudoParameterOverrides: { accountId: '123456789012', region },
          }).diagnostics ?? []) as Diagnostic[];
          // 必須プロパティを抜いた（エンジンのスキーマ検査が止める）変異体は、エンジンの持ち場
          if (ds.some((d) => d.source !== 'CUSTOM' && (d.severity === 'ERROR' || d.severity === 'FATAL'))) continue;
          if (ds.some((d) => d.source === 'CUSTOM' && d.ruleId === rule.id)) {
            const c = { rule: rule.id, key };
            out.set(`${rule.id} ${key}`, c);
            onClaim?.(c, mutant);
          }
        }
      }
    }
    // サービスごとにエンジンを作り直す。解放しないと WASM のメモリが尽きて 60 サービス目あたりで落ちる
    for (const e of engines.values()) e.free?.();
  }
  return [...out.values()].sort((a, b) => `${a.rule} ${a.key}`.localeCompare(`${b.rule} ${b.key}`));
}

/** meta.yaml#omissionFails（実測の証拠付きで宣言した主張）。 */
export function declaredOmissions(): Set<string> {
  const out = new Set<string>();
  for (const r of BUNDLED_RULES) {
    const meta = YAML.parse(fs.readFileSync(path.join(ROOT, 'rules', r.service, r.id, 'meta.yaml'), 'utf8'));
    for (const k of meta.omissionFails ?? []) out.add(`${r.id} ${k}`);
  }
  return out;
}

export const BASELINE = path.join(ROOT, 'rules', '_omission-baseline.txt');

export function readOmissionBaseline(): Set<string> {
  if (!fs.existsSync(BASELINE)) return new Set();
  return new Set(fs.readFileSync(BASELINE, 'utf8').split('\n').map((l) => l.trim()).filter((l) => l && !l.startsWith('#')).map((l) => l.split(/\s+/).slice(0, 2).join(' ')));
}

/** 宣言もベースラインも無い主張は問題。主張しなくなったのにベースラインに残る行も問題（ラチェット）。 */
export function omissionProblems(claims: OmissionClaim[], declared: Set<string>, baseline: Set<string>): string[] {
  const found = new Set(claims.map((c) => `${c.rule} ${c.key}`));
  const problems: string[] = [];
  for (const c of found) {
    if (!declared.has(c) && !baseline.has(c)) {
      const [rule, key] = c.split(' ');
      problems.push(`${rule} fires when ${key} is omitted from its pass template, i.e. it claims that omitting it fails the deploy. `
        + 'Deploy the pass template without it (bench/verify-rule.sh); if CREATE fails, add the key to meta.omissionFails and the error to repro.evidence; if it deploys, the rule is reading an omitted value as a value.');
    }
  }
  for (const b of baseline) if (!found.has(b)) problems.push(`rules/_omission-baseline.txt: '${b}' is no longer claimed; delete the line`);
  for (const d of declared) if (!found.has(d)) problems.push(`meta.omissionFails of ${d.split(' ')[0]}: '${d.split(' ')[1]}' is not claimed by the rule (it does not fire when that property is omitted); drop it`);
  return problems;
}

/**
 * 実測用に、主張ごとのルールの写しを書き出す: <out>/<service>/<rule>--<n>/ に meta.yaml（repro.expect を外したもの）、
 * pass テンプレート、fail テンプレート = 変異体。bench/verify-rule.sh を CDKPF_RULES_DIR=<out> で
 * <rule>--<n> --fail-only と回すと、exit 0（落ちた: 主張は正しい）か 2（通った: 省略を値と読んでいる）が出る。
 * 対応表は <out>/claims.tsv（copy-id, rule-id, key）。
 */
export function emitMutants(out: string, filters: string[]): OmissionClaim[] {
  const rows: string[] = [];
  const n = new Map<string, number>();
  const claims = omissionClaims(filters, (c, mutant) => {
    const rule = BUNDLED_RULES.find((r) => r.id === c.rule)!;
    const i = (n.get(c.rule) ?? 0) + 1;
    n.set(c.rule, i);
    const copy = `${c.rule}--${i}`;
    const src = path.join(ROOT, 'rules', rule.service, rule.id);
    const dst = path.join(out, rule.service, copy);
    fs.mkdirSync(path.join(dst, 'templates'), { recursive: true });
    const meta = fs.readFileSync(path.join(src, 'meta.yaml'), 'utf8').split('\n').filter((l) => !/^\s+expect:/.test(l)).join('\n');
    fs.writeFileSync(path.join(dst, 'meta.yaml'), meta);
    fs.copyFileSync(path.join(src, 'templates', 'pass.template.json'), path.join(dst, 'templates', 'pass.template.json'));
    fs.writeFileSync(path.join(dst, 'templates', 'fail.template.json'), JSON.stringify(mutant, null, 2));
    rows.push(`${copy}\t${c.rule}\t${c.key}`);
  });
  fs.writeFileSync(path.join(out, 'claims.tsv'), rows.join('\n') + '\n');
  return claims;
}

if (require.main === module) {
  const emitAt = process.argv.indexOf('--emit-mutants');
  if (emitAt >= 0) {
    const out = path.resolve(process.argv[emitAt + 1]);
    const ids = process.argv.slice(2).filter((a, i) => !a.startsWith('--') && i !== emitAt - 1);
    const claims = emitMutants(out, ids);
    console.error(`-- wrote ${claims.length} mutants to ${out} (claims.tsv)`);
    process.exit(0);
  }
  const write = process.argv.includes('--write-baseline');
  const filters = process.argv.slice(2).filter((a) => !a.startsWith('--'));
  const claims = omissionClaims(filters);
  if (write) {
    const declared = declaredOmissions();
    const rows = claims.map((c) => `${c.rule} ${c.key}`).filter((k) => !declared.has(k));
    fs.writeFileSync(BASELINE, [
      '# scripts/omission-sweep.ts のラチェット。ルールが「このプロパティを省略するとデプロイが落ちる」と',
      '# 主張している（pass テンプレートから抜くと鳴る）のに、その主張の実測が meta.omissionFails に',
      '# 無いもの。2026-11-25 時点の既存分を凍結した見直しリスト: 増やせず、実測したら meta へ移すか',
      '# ルールを直して行を消す。',
      '#',
      '# 書式: <rule-id> <ResourceType.Property.Path>',
      '',
      ...rows,
      '',
    ].join('\n'));
    console.error(`wrote ${rows.length} lines to ${BASELINE}`);
  }
  const problems = filters.length ? [] : omissionProblems(claims, declaredOmissions(), readOmissionBaseline());
  for (const p of problems) console.log(p);
  console.error(`-- ${claims.length} omission claims; ${problems.length} problem(s)`);
  process.exitCode = problems.length ? 1 : 0;
}
