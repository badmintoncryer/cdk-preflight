/**
 * 参照の差し替え回帰（誤検知の根絶）: ルールが Ref / Fn::GetAtt を文字列リテラルとして読んでいないか。
 *
 * エンジンの resolve() は Ref / GetAtt を参照先の論理 ID（文字列）に解決する。is_string だけで
 * リテラルと見なすルールは、`{ "Ref": "MyBucket" }` を "MyBucket" という値として検査し、
 * デプロイ時には別の値になるものを誤検知する（誤検知の 4 つの形のうち「参照をリテラルと読む」）。
 *
 * 各ルールの pass テンプレートを出発点に、そのルールが見るリソースタイプの文字列の葉を 1 つずつ
 * Ref / GetAtt（テンプレートに足した、どのルールも見ないリソース PfRefTarget へ）に差し替えて評価する。
 * pass テンプレートは鳴らないので、差し替えた後に鳴るなら、その鳴りは差し替えた参照のせい。
 * 参照の値はデプロイまで分からないので、鳴ってよいのは「どんな値でも落ちる」ときだけで、
 * それは差し替える前から鳴っているはず。よって原則すべて誤検知。エンジン組み込みのルールが
 * ERROR / FATAL を出す差し替え（その位置に参照が書けない）は対象外。
 *
 * 評価エラー（ルールの実行時エラー）は service のルールを丸ごと止めるので、ベースラインに関係なく常に失敗。
 *
 *   npx ts-node --transpile-only --project test/tsconfig.json scripts/reference-sweep.ts          （全行を出す）
 *   ... scripts/reference-sweep.ts --check   （CI: rules/_reference-baseline.txt と突き合わせる）
 *
 * 出力: <rule-id> <Ref|GetAtt> <ResourceType>.<property path> <message>
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { deployEnvironmentModule, loadEngine, mergeRuleModules, validateTemplate } from '../src/private/enforce';
import { BUNDLED_LIBS, BUNDLED_RULES } from '../src/rules.generated';

const ROOT = path.join(__dirname, '..');
export const BASELINE = path.join(ROOT, 'rules', '_reference-baseline.txt');
const ACCOUNT = '123456789012';

export interface ReferenceHit {
  readonly rule: string;
  readonly kind: 'Ref' | 'GetAtt';
  readonly at: string;
  /** undefined のときはルールの発火、文字列のときは評価エラー */
  readonly message: string;
  readonly evalError: boolean;
}

/** 差し替えてよい文字列の葉のパス。配列は先頭要素だけ、組み込み関数の中と "." を含むキーは見ない。 */
function stringPaths(o: unknown, prefix: string[] = [], depth = 4): string[][] {
  if (depth === 0 || !o || typeof o !== 'object') return [];
  const out: string[][] = [];
  const entries: [string, unknown][] = Array.isArray(o) ? o.slice(0, 1).map((v, i) => [String(i), v]) : Object.entries(o);
  for (const [k, v] of entries) {
    if (k.startsWith('Fn::') || k === 'Ref' || k.includes('.')) continue;
    if (typeof v === 'string') out.push([...prefix, k]);
    else out.push(...stringPaths(v, [...prefix, k], depth - 1));
  }
  return out;
}

function setPath(o: any, p: string[], v: unknown): void {
  let cur = o;
  for (const s of p.slice(0, -1)) cur = cur[s];
  cur[p[p.length - 1]] = v;
}

export function referenceHits(log: (s: string) => void = () => {}): ReferenceHit[] {
  const engine = loadEngine();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cdkpf-refs-'));
  const file = path.join(tmp, 'm.json');
  const out: ReferenceHit[] = [];
  const services = [...new Set(BUNDLED_RULES.map((r) => r.service))].sort();
  for (const service of services) {
    log(service);
    const rules = BUNDLED_RULES.filter((r) => r.service === service);
    const engines = new Map<string, any>();
    const engineFor = (region: string): any => {
      if (!engines.has(region)) {
        engines.set(region, new engine.RegoEngine({
          customRules: [
            ...BUNDLED_LIBS.map((l) => ({ name: l.name, content: l.rego })),
            ...mergeRuleModules(rules),
            deployEnvironmentModule(region, ACCOUNT),
          ],
        }));
      }
      return engines.get(region);
    };
    for (const rule of rules) {
      const region = rule.fixtureRegion ?? 'us-east-1';
      const passFile = path.join(ROOT, 'rules', service, rule.id, 'templates', 'pass.template.json');
      if (!fs.existsSync(passFile)) continue;
      const pass = JSON.parse(fs.readFileSync(passFile, 'utf8'));
      const seen = new Set<string>();
      for (const [lid, res] of Object.entries<any>(pass.Resources ?? {})) {
        if (!rule.resourceTypes.includes(res?.Type) || !res.Properties) continue;
        for (const p of stringPaths(res.Properties)) {
          for (const kind of ['Ref', 'GetAtt'] as const) {
            const at = `${res.Type}.${p.join('.')}`;
            if (seen.has(`${kind} ${at}`)) continue;
            const m = JSON.parse(JSON.stringify(pass));
            m.Resources.PfRefTarget = { Type: 'AWS::CloudFormation::WaitConditionHandle' };
            setPath(m.Resources[lid].Properties, p, kind === 'Ref' ? { Ref: 'PfRefTarget' } : { 'Fn::GetAtt': ['PfRefTarget', 'Arn'] });
            fs.writeFileSync(file, JSON.stringify(m));
            let ds: any[];
            try {
              ds = validateTemplate(engineFor(region), new engine.TemplateFile(file), {
                pseudoParameterOverrides: { accountId: ACCOUNT, region },
              }).diagnostics ?? [];
            } catch (e) {
              seen.add(`${kind} ${at}`);
              out.push({ rule: rule.id, kind, at, message: String(e).replace(/\s+/g, ' ').slice(0, 300), evalError: true });
              // 落ちたエンジンは作り直す
              for (const x of engines.values()) x.free?.();
              engines.clear();
              continue;
            }
            if (ds.some((d) => d.source !== 'CUSTOM' && (d.severity === 'ERROR' || d.severity === 'FATAL'))) continue;
            const hit = ds.find((d) => d.source === 'CUSTOM' && d.ruleId === rule.id);
            if (hit) {
              seen.add(`${kind} ${at}`);
              out.push({ rule: rule.id, kind, at, message: String(hit.message ?? '').replace(/\s+/g, ' '), evalError: false });
            }
          }
        }
      }
    }
    for (const x of engines.values()) x.free?.();
  }
  fs.rmSync(tmp, { recursive: true, force: true });
  return out;
}

/** "<rule> <kind> <at>" の集合。 */
export function readBaseline(file = BASELINE): Set<string> {
  if (!fs.existsSync(file)) return new Set();
  return new Set(fs.readFileSync(file, 'utf8').split('\n').map((l) => l.replace(/#.*$/, '').trim()).filter(Boolean)
    .map((l) => l.split(/\s+/).slice(0, 3).join(' ')));
}

/** 評価エラー、ベースラインに無い発火、もう鳴らないベースライン行（ラチェット）が問題。 */
export function referenceProblems(hits: ReferenceHit[], baseline: Set<string>): string[] {
  const problems: string[] = [];
  const found = new Set<string>();
  for (const h of hits) {
    const k = `${h.rule} ${h.kind} ${h.at}`;
    found.add(k);
    if (h.evalError) {
      problems.push(`${h.rule}: evaluating a template with a ${h.kind} at ${h.at} is a runtime error, which stops every rule of its service: ${h.message}`);
    } else if (!baseline.has(k)) {
      problems.push(`${h.rule} fires when ${h.at} is a ${h.kind}: ${h.message}\n`
        + '  The rule reads the reference as a literal (resolve() returns the logical ID). Skip values that name a resource '
        + '(`not input.resources[v]`), or read the raw property, so a reference mutes the rule.');
    }
  }
  for (const k of baseline) {
    if (!found.has(k)) problems.push(`${k} no longer fires: remove it from rules/_reference-baseline.txt`);
  }
  return problems;
}

if (require.main === module) {
  const hits = referenceHits((s) => process.stderr.write(`${s} `));
  process.stderr.write('\n');
  if (process.argv.includes('--check')) {
    const problems = referenceProblems(hits, readBaseline());
    for (const p of problems) console.log(p);
    console.error(`-- ${problems.length} problem(s)`);
    process.exitCode = problems.length ? 1 : 0;
  } else {
    for (const h of hits) console.log([h.rule, h.kind, h.at, h.evalError ? `EVAL-ERROR ${h.message}` : h.message].join('\t'));
    console.error(`-- ${hits.length} hits from ${new Set(hits.map((h) => h.rule)).size} rules`);
  }
}
