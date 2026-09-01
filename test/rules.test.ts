/**
 * ルール単体テスト（エンジン直接評価・表駆動）。
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
import { loadEngine } from '../src/private/enforce';
import { BUNDLED_RULES } from '../src/rules.generated';

interface Diagnostic {
  ruleId: string;
  severity: string;
  message: string;
  source?: string;
}

const engine = loadEngine();

// エンジン初期化（WASM）と評価は重いので、全ルールを 1 エンジンに載せ、
// フィクスチャごとの診断結果をキャッシュして全テストで共有する。
let sharedEngine: any;
function engineInstance(): any {
  if (!sharedEngine) {
    sharedEngine = new engine.RegoEngine({
      customRules: BUNDLED_RULES.map((r) => ({ name: r.id, content: r.rego })),
    });
  }
  return sharedEngine;
}

const diagCache = new Map<string, Diagnostic[]>();
function diagnose(templateFile: string): Diagnostic[] {
  if (!diagCache.has(templateFile)) {
    const report = engineInstance().validateDetailed(new engine.TemplateFile(templateFile), {});
    diagCache.set(templateFile, (report.diagnostics ?? []) as Diagnostic[]);
  }
  return diagCache.get(templateFile)!;
}

function fixturePath(rule: (typeof BUNDLED_RULES)[number], kind: 'fail' | 'pass'): string {
  return path.join(__dirname, '..', 'rules', rule.service, rule.id, 'templates', `${kind}.template.json`);
}

const blockers = (ds: Diagnostic[]) =>
  ds.filter((d) => d.source !== 'CUSTOM' && (d.severity === 'ERROR' || d.severity === 'FATAL'));

test('engine is resolvable (bundled in aws-cdk-lib)', () => {
  expect(engine).toBeDefined();
});

describe.each(BUNDLED_RULES.map((r) => [r.id, r] as const))('%s', (_id, rule) => {
  test('fires on the fail template', () => {
    const ds = diagnose(fixturePath(rule, 'fail'));
    const mine = ds.filter((d) => d.ruleId === rule.id && d.source === 'CUSTOM');
    expect(mine.length).toBeGreaterThanOrEqual(1);
    for (const d of mine) {
      expect(d.message).toBeTruthy();
    }
  });

  test('stays silent on the pass template', () => {
    const ds = diagnose(fixturePath(rule, 'pass'));
    // 当該ルールはもちろん、他の pf- ルールの誤爆も無いこと
    expect(ds.filter((d) => d.source === 'CUSTOM')).toHaveLength(0);
  });

  test('does not duplicate a built-in blocker (fail template)', () => {
    const ds = diagnose(fixturePath(rule, 'fail'));
    expect(blockers(ds)).toHaveLength(0);
  });

  test('pass template is clean for the built-in engine', () => {
    const ds = diagnose(fixturePath(rule, 'pass'));
    expect(blockers(ds)).toHaveLength(0);
  });
});

describe('delegation to built-in rules', () => {
  test('a dangling StartAt is left to engine rule E3601 (not duplicated)', () => {
    const tpl = {
      Resources: {
        SM: {
          Type: 'AWS::StepFunctions::StateMachine',
          Properties: {
            RoleArn: 'arn:aws:iam::123456789012:role/service-role/StatesExecutionRole',
            DefinitionString: JSON.stringify({ StartAt: 'MISSING', States: { A: { Type: 'Succeed' } } }),
          },
        },
      },
    };
    const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'cdk-preflight-rules-')), 'startat.template.json');
    fs.writeFileSync(file, JSON.stringify(tpl));
    const ds = diagnose(file);
    // エンジン組み込みの E3601（ERROR/CFN_LINT）が StartAt の参照切れを検出する
    expect(ds.some((d) => d.ruleId === 'E3601' && d.severity === 'ERROR')).toBe(true);
    // 自前ルールは StartAt を重複報告しない（Next/Default/Choices 専任 = 重複ガード方針）
    expect(ds.filter((d) => d.source === 'CUSTOM')).toHaveLength(0);
  });
});
