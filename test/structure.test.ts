/**
 * リポジトリ構造の lint テスト。
 * rules/ ディレクトリの完全性と、生成物（rules.generated.ts / docs/rules.md）の鮮度を担保する。
 */
import * as fs from 'fs';
import * as path from 'path';
import { collectLibs, collectRules, evidenceProblem, renderDocs, renderGenerated } from '../scripts/bundle-rules';
import { BUNDLED_LIBS, BUNDLED_RULES } from '../src/rules.generated';

const root = path.join(__dirname, '..');

test('rules/ passes all structural validations', () => {
  // collectRules は不足ファイル・メタ不整合・ID 不一致で throw する
  const rules = collectRules(root);
  expect(rules.length).toBeGreaterThanOrEqual(9);
});

test('rule ids are unique', () => {
  const ids = collectRules(root).map((r) => r.id);
  expect(new Set(ids).size).toBe(ids.length);
});

test('src/rules.generated.ts is up to date', () => {
  const expected = renderGenerated(collectRules(root), collectLibs(root));
  const actual = fs.readFileSync(path.join(root, 'src', 'rules.generated.ts'), 'utf8');
  expect(actual).toBe(expected);
});

test('docs/rules.md is up to date', () => {
  const expected = renderDocs(collectRules(root));
  const actual = fs.readFileSync(path.join(root, 'docs', 'rules.md'), 'utf8');
  expect(actual).toBe(expected);
});

test('every bundled rule declares the package cdk_preflight and rego.v1', () => {
  for (const r of BUNDLED_RULES) {
    expect(r.rego).toContain('package cdk_preflight');
    expect(r.rego).toContain('import rego.v1');
  }
});

test('shared lib modules are helper-only and use the _pf_ prefix convention', () => {
  for (const l of BUNDLED_LIBS) {
    expect(l.rego).toContain('package cdk_preflight');
    expect(l.rego).not.toContain('violation contains');
    // every top-level rule/function in a lib starts with _pf_<lib>_
    for (const m of l.rego.matchAll(/^([A-Za-z_][A-Za-z0-9_]*)\s*(\(|:=|contains)/gm)) {
      expect(m[1]).toMatch(/^_pf_/);
    }
  }
});

test('repro evidence is required, and real-deploy must quote a bench run', () => {
  // 実データ側: collectRules が全ルールを通す = 227 件すべて要件を満たしている
  expect(evidenceProblem({ method: 'doc-only', evidence: 'schema says so' })).toBeUndefined();
  expect(evidenceProblem({ method: 'research-case', evidence: 'issue #123, 2026-09-03' })).toBeUndefined();
  expect(evidenceProblem({ method: 'real-deploy', evidence: '' })).toMatch(/required/);
  expect(evidenceProblem({ method: 'doc-only' })).toMatch(/required/);
  // 実機を回さずに real-deploy を自称するケースを弾く
  expect(evidenceProblem({ method: 'real-deploy', evidence: 'verified locally' })).toMatch(/bench run/);
  expect(evidenceProblem({ method: 'real-deploy', evidence: 'bench 2026-09-03: rolled back' })).toMatch(/bench run/);
  expect(
    evidenceProblem({
      method: 'real-deploy',
      evidence: 'bench 2026-09-03 ap-northeast-1: TTL 7200 -> CREATE_FAILED ROLLBACK_COMPLETE',
    }),
  ).toBeUndefined();
});

/**
 * 1 つの rule body に裸の `some x` が 2 つ以上あると、エンジンは 2 つ目の局所変数を
 * 外側の反復ごとに定義し直そうとして "duplicated definition of local variable" で落ちる。
 * 落ちるのはそのルールだけではなくカスタムパッケージ全体なので、テンプレート次第で
 * 全ルールが黙って無効になる（issue #150）。2 つ目以降は `some k, v in coll` で書く。
 */
function bareSomeOffenders(name: string, rego: string): string[] {
  const offenders: string[] = [];
  let body: string[] | undefined;
  for (const line of rego.split('\n')) {
    if (body === undefined) {
      if (/\{\s*$/.test(line)) body = [];
      continue;
    }
    if (line === '}') {
      const bare = body.filter((l) => /^\t*some\s+[A-Za-z_][A-Za-z0-9_]*\s*$/.test(l));
      if (bare.length >= 2) offenders.push(`${name}: ${bare.map((l) => l.trim()).join(' + ')}`);
      body = undefined;
      continue;
    }
    body.push(line);
  }
  return offenders;
}

test('no rego body declares two bare `some` variables', () => {
  // 検出器そのものが空振りしていないことの確認
  expect(bareSomeOffenders('probe', 'violation contains 1 if {\n\tsome a\n\tsome b\n}\n')).toHaveLength(1);

  const modules = [
    ...BUNDLED_RULES.map((r) => ({ name: r.id, rego: r.rego })),
    ...BUNDLED_LIBS.map((l) => ({ name: l.name, rego: l.rego })),
  ];
  expect(modules.flatMap((m) => bareSomeOffenders(m.name, m.rego))).toEqual([]);
});
