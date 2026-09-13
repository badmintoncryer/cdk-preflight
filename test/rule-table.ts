/**
 * ルール単体テストのハーネス（エンジン直接評価・表駆動）。
 *
 * 表そのものは test/rules.shard*.test.ts が {@link describeRuleTable} 経由で回す。
 * 4390 枚の評価を 1 ファイルに置くと jest のワーカー 1 本に固定されるので、
 * ルール ID 順のモジュロで分割して並列に乗せている（1 ファイル 481s -> 6 分割）。
 * 評価コストはエンジンに載るルール本数にほとんど依存しない（全パック 269ms/枚 vs
 * 刈り込み後 200ms/枚、実測 2026-09-13）ので、シャードでも全ルールを載せて
 * 「他のルールも pass テンプレートで誤爆しない」横断ガードを据え置く。
 *
 * 各ルールについて:
 *  - fail テンプレート → 当該ルールの CUSTOM 診断が 1 件以上出る
 *  - pass テンプレート → 当該ルールの診断が出ない
 *  - 【重複ガード】fail テンプレートに対して、組み込みエンジン（SCHEMA / CFN_LINT）の
 *    ERROR/FATAL が出ない = 「エンジンが既に止める制約」をルールパックに重複実装していない
 *  - 【フィクスチャ健全性】pass テンプレートにも組み込み ERROR/FATAL が出ない
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { deployEnvironmentModule, loadEngine, mergeRuleModules, prune, templateResourceTypes } from '../src/private/enforce';
import { BUNDLED_LIBS, BUNDLED_RULES } from '../src/rules.generated';

export interface Diagnostic {
  ruleId: string;
  severity: string;
  message: string;
  source?: string;
}

export const engine = loadEngine();

/** フィクスチャ評価時のデプロイリージョン（deploy_region 注入のハーネス既定）。 */
const HARNESS_REGION = 'us-east-1';

// エンジン初期化（WASM）と評価は重いので、リージョンごとに 1 エンジンに全ルールを
// 載せてキャッシュし、フィクスチャの診断結果も共有する。本番の enforce プラグインと
// 同じ deployEnvironmentModule を注入する（ローダー契約のカップリングテストを兼ねる）。
const engineCache = new Map<string, any>();
function engineInstance(region?: string): any {
  const key = region ?? '';
  if (!engineCache.has(key)) {
    // 本番と同じく service 単位に結合して載せる。これで全ルールのフィクスチャ検査が
    // そのまま「結合しても挙動が変わらない」ことの検査になる。
    const customRules = [
      ...BUNDLED_LIBS.map((l) => ({ name: l.name, content: l.rego })),
      ...mergeRuleModules(BUNDLED_RULES),
    ];
    if (region) customRules.push(deployEnvironmentModule(region, '123456789012'));
    engineCache.set(key, new engine.RegoEngine({ customRules }));
  }
  return engineCache.get(key);
}

const diagCache = new Map<string, Diagnostic[]>();
export function diagnose(templateFile: string, region: string = HARNESS_REGION): Diagnostic[] {
  if (!diagCache.has(templateFile)) {
    const report = engineInstance(region).validateDetailed(new engine.TemplateFile(templateFile), {
      pseudoParameterOverrides: { accountId: '123456789012', region },
    });
    diagCache.set(templateFile, (report.diagnostics ?? []) as Diagnostic[]);
  }
  return diagCache.get(templateFile)!;
}

/**
 * 一時ファイルに書いて評価する。region を渡すと擬似パラメータ解決と
 * deploy_region 注入の両方を有効にする（省略時はどちらも無し＝リージョン不明の挙動）。
 */
export function diagnoseTemplate(tpl: unknown, region?: string): Diagnostic[] {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cdk-preflight-rules-')), 'inline.template.json');
  fs.writeFileSync(file, JSON.stringify(tpl));
  const options = region
    ? { pseudoParameterOverrides: { accountId: '123456789012', region } }
    : {};
  const report = engineInstance(region).validateDetailed(new engine.TemplateFile(file), options);
  return (report.diagnostics ?? []) as Diagnostic[];
}

function fixturePath(rule: (typeof BUNDLED_RULES)[number], kind: 'fail' | 'pass'): string {
  return path.join(__dirname, '..', 'rules', rule.service, rule.id, 'templates', `${kind}.template.json`);
}

const blockers = (ds: Diagnostic[]) =>
  ds.filter((d) => d.source !== 'CUSTOM' && (d.severity === 'ERROR' || d.severity === 'FATAL'));

/** ルール表のうち `i % total === shard` のぶんを回す。 */
export function describeRuleTable(shard: number, total: number): void {
  describe.each(BUNDLED_RULES.filter((_r, i) => i % total === shard).map((r) => [r.id, r] as const))('%s', (_id, rule) => {
    // meta.fixtureRegion: rules about the deploy region itself (e.g. "CLOUDFRONT scope only in us-east-1")
    // need their fixtures evaluated somewhere other than the harness default.
    const region = rule.fixtureRegion ?? HARNESS_REGION;
    test('fires on the fail template', () => {
      const ds = diagnose(fixturePath(rule, 'fail'), region);
      const mine = ds.filter((d) => d.ruleId === rule.id && d.source === 'CUSTOM');
      expect(mine.length).toBeGreaterThanOrEqual(1);
      for (const d of mine) {
        expect(d.message).toBeTruthy();
      }
    });

    test('stays silent on the pass template', () => {
      const ds = diagnose(fixturePath(rule, 'pass'), region);
      // 当該ルールはもちろん、他の pf- ルールの誤爆も無いこと
      expect(ds.filter((d) => d.source === 'CUSTOM')).toHaveLength(0);
    });

    // enforce プラグインは meta.resourceTypes を使ってルールを刈り込む（固定費の削減）。
    // 宣言から漏れたリソースタイプがあるとそのルールは黙って載らなくなる = 見逃しになるので、
    // 「自分の fail テンプレートに対して刈り残る」ことを全ルールで機械的に確認する。
    test('survives resource-type pruning of its own fail template', () => {
      const types = templateResourceTypes([fixturePath(rule, 'fail')]);
      expect(prune(BUNDLED_RULES, types).map((r) => r.id)).toContain(rule.id);
    });

    test('does not duplicate a built-in blocker (fail template)', () => {
      const ds = diagnose(fixturePath(rule, 'fail'), region);
      const found = blockers(ds);
      // このテストは二役: 新規ルールに対しては「エンジンと重複したので書くな」、
      // 既存ルールに対しては「エンジンが追いついたので退役させろ」の合図になる。
      // 後者は aws-cdk-lib を上げた時にだけ赤くなる（bench/out/redundancy.jsonl と同じ判定）。
      expect(found.map((d) => `${d.severity}/${d.source}/${d.ruleId}: ${d.message}`
        + ` >>> the bundled engine now blocks ${rule.id} by itself — retire it:`
        + ` rm -rf rules/${rule.service}/${rule.id}/ && npx projen bundle-rules`
        + ' (AGENTS.md "Rule lifecycle"; npx projen redundancy-scan lists them all)'))
        .toHaveLength(0);
    });

    test('pass template is clean for the built-in engine', () => {
      const ds = diagnose(fixturePath(rule, 'pass'), region);
      expect(blockers(ds)).toHaveLength(0);
    });
  });
}
