/**
 * リポジトリ構造の lint テスト。
 * rules/ ディレクトリの完全性と、生成物（rules.generated.ts / docs/rules.md）の鮮度を担保する。
 */
import * as fs from 'fs';
import * as path from 'path';
import { collectLibs, collectRules, docOnlyProblem, evidenceProblem, headerProblem, nameCollisions, renderDocs, renderGenerated, severityProblem, topLevelNames } from '../scripts/bundle-rules';
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

/**
 * enforce は service 単位にモジュールを結合するとき package / import 行を落とすので、
 * それ以外のヘッダを書いたルールは黙って import 無しで結合されてしまう。
 */
test('a rule may not carry any header other than package cdk_preflight + import rego.v1', () => {
  expect(headerProblem('package cdk_preflight\n\nimport rego.v1\n')).toBeUndefined();
  expect(headerProblem('package other\n\nimport rego.v1\n')).toMatch(/package cdk_preflight/);
  expect(headerProblem('package cdk_preflight\n')).toMatch(/import rego.v1/);
  expect(headerProblem('package cdk_preflight\n\nimport rego.v1\nimport data.foo\n')).toMatch(/no other import/);
  // 実データ側: collectRules / collectLibs が全モジュールを通している
  for (const m of [...BUNDLED_RULES, ...BUNDLED_LIBS]) expect(headerProblem(m.rego)).toBeUndefined();
});

test('top-level names are collected, and `violation` is not one of them', () => {
  const rego = [
    'package cdk_preflight',
    '',
    'import rego.v1',
    '',
    'default _pf_x_flag := false',
    '_pf_x_set := {"a"}',
    '_pf_x_fn(v) := v if is_string(v)',
    '_pf_x_pred if { true }',
    'violation contains 1 if { true }',
    '\t_pf_x_indented := 1',
  ].join('\n');
  expect([...topLevelNames(rego)].sort()).toEqual(['_pf_x_flag', '_pf_x_fn', '_pf_x_pred', '_pf_x_set']);
});

/**
 * 全ルールが同じ package なので、別モジュールに書いた同名ヘルパーは増分定義として
 * 黙って合流する（結合の有無に関わらず）。共有したい定義は rules/_lib/ に置く。
 */
test('no two rules define the same top-level name', () => {
  expect(nameCollisions([
    { name: 'pf-a', rego: '_pf_shared := 1\n' },
    { name: 'pf-b', rego: '_pf_shared := 2\n' },
  ])).toEqual([expect.stringContaining('_pf_shared is defined by pf-a and pf-b')]);
  // 同じモジュール内の増分定義（同名を複数回書く書き方）は正常
  expect(nameCollisions([{ name: 'pf-a', rego: '_pf_j(v) := v if is_object(v)\n_pf_j(v) := {} if is_string(v)\n' }])).toEqual([]);

  expect(nameCollisions([
    ...collectRules(root).map((r) => ({ name: r.id, rego: r.rego })),
    ...collectLibs(root).map((l) => ({ name: l.name, rego: l.rego })),
  ])).toEqual([]);
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

test('meta.severity has to match the severity the rego actually emits', () => {
  const rego = (sev: string) => `violation contains make_diag_full("pf-x", "${sev}", name,\n\t"Properties.A", "m", "f", "u") if { true }`;
  expect(severityProblem('pf-x', 'ERROR', rego('ERROR'))).toBeUndefined();
  expect(severityProblem('pf-x', 'WARN', rego('WARN'))).toBeUndefined();
  // 実行時の severity は rego 側にあるので、meta だけ書き換えても効かない
  expect(severityProblem('pf-x', 'WARN', rego('ERROR'))).toMatch(/emits ERROR but meta.severity is WARN/);
  // 同じルールの複数の violation ブロックが食い違うのも弾く
  expect(severityProblem('pf-x', 'WARN', `${rego('WARN')}\n${rego('ERROR')}`)).toMatch(/emits ERROR/);
  // 別ルールの id を持つ呼び出しは見ない（_lib のヘルパー等を巻き込まないため）
  expect(severityProblem('pf-x', 'WARN', `${rego('WARN')}\n${rego('ERROR').replace('pf-x', 'pf-y')}`)).toBeUndefined();
  expect(severityProblem('pf-x', 'ERROR', 'violation contains 1 if { true }')).toMatch(/must emit its own rule id/);
});

test('doc-only rules are warnings: they must not fail synth', () => {
  expect(docOnlyProblem({ method: 'doc-only' }, 'WARN')).toBeUndefined();
  expect(docOnlyProblem({ method: 'doc-only' }, 'ERROR')).toMatch(/requires severity WARN/);
  // 実機・研究ケースの証拠があるものは ERROR のままでよい
  expect(docOnlyProblem({ method: 'real-deploy' }, 'ERROR')).toBeUndefined();
  expect(docOnlyProblem({ method: 'research-case' }, 'ERROR')).toBeUndefined();
});

test('every doc-only rule ships as a warning', () => {
  const docOnly = collectRules(root).filter((r) => r.severity !== 'ERROR');
  expect(docOnly.length).toBeGreaterThan(0);
  for (const r of docOnly) expect(r.severity).toBe('WARN');
});
