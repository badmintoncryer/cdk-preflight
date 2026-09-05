/**
 * リポジトリ構造の lint テスト。
 * rules/ ディレクトリの完全性と、生成物（rules.generated.ts / docs/rules.md）の鮮度を担保する。
 */
import * as fs from 'fs';
import * as path from 'path';
import { collectRules, evidenceProblem, renderDocs, renderGenerated } from '../scripts/bundle-rules';
import { BUNDLED_RULES } from '../src/rules.generated';

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
  const expected = renderGenerated(collectRules(root));
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
