/**
 * リポジトリ構造の lint テスト。
 * rules/ ディレクトリの完全性と、生成物（rules.generated.ts / docs/rules.md）の鮮度を担保する。
 */
import * as fs from 'fs';
import * as path from 'path';
import * as YAML from 'yaml';
import { collectLibs, collectRules, renderDocs, renderGenerated } from '../scripts/bundle-rules';
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

test('doc-only repro rules carry an explanation', () => {
  for (const r of BUNDLED_RULES) {
    const meta = YAML.parse(
      fs.readFileSync(path.join(root, 'rules', r.service, r.id, 'meta.yaml'), 'utf8'),
    );
    if (meta.repro.method === 'doc-only') {
      expect(meta.repro.evidence).toBeTruthy();
    }
  }
});
