/**
 * リポジトリ構造の lint テスト。
 * rules/ ディレクトリの完全性と、生成物（rules.generated.ts / docs/rules.md）の鮮度を担保する。
 */
import * as fs from 'fs';
import * as path from 'path';
import { boundaryProblem, collectLibs, collectRules, docOnlyProblem, evidenceProblem, headerProblem, nameCollisions, renderDocs, renderGenerated, renderSupported, severityProblem, topLevelNames } from '../scripts/bundle-rules';
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

test('the README resource-type list is up to date', () => {
  const expected = renderSupported(collectRules(root));
  const actual = fs.readFileSync(path.join(root, 'README.md'), 'utf8');
  expect(actual).toContain(expected);
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

/**
 * AGENTS.md 原則 2 の「両方のフィクスチャが境界に乗る」を機械で見る。検出はヒューリスティック
 * （rego のしきい値とテンプレートに現れる量の突き合わせ）なので、意味を持たないルールは
 * rules/_boundary-exceptions.txt に理由付きで逃がす。例外ファイルは残作業リストも兼ねていて、
 * 直ったのに行が残っているとテストが落ちる——緩いまま寝かせる余地も、直したのに記録が
 * 古いままになる余地も残さない。
 */
function boundaryExceptions(): Map<string, string> {
  const raw = fs.readFileSync(path.join(root, 'rules', '_boundary-exceptions.txt'), 'utf8');
  const out = new Map<string, string>();
  for (const line of raw.split('\n')) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const [id, ...reason] = t.split(/\s\s+/);
    out.set(id, reason.join(' '));
  }
  return out;
}

const fixture = (value: string) => JSON.stringify({ Resources: { X: { Type: 'AWS::X::Y', Properties: { V: value } } } });

test('boundaryProblem pins both the constant and the operator', () => {
  const rego = 'violation contains 1 if {\n\tcount(v) < 20\n}\n';
  expect(boundaryProblem(rego, fixture('x'.repeat(19)), fixture('x'.repeat(20)))).toBeUndefined();
  expect(boundaryProblem(rego, fixture('short'), fixture('x'.repeat(20)))).toMatch(/fail template has no 19/);
  expect(boundaryProblem(rego, fixture('x'.repeat(19)), fixture('x'.repeat(26)))).toMatch(/pass template has no 20/);
  // 数値のしきい値はテンプレートを生で走査するので、文字列に包まれた数も拾う
  const numeric = 'violation contains 1 if {\n\tto_number(v) > 300\n}\n';
  expect(boundaryProblem(numeric, fixture('301'), fixture('300'))).toBeUndefined();
  // 存在チェック（0/1）と小数のしきい値には隣の値が定義できないので見ない
  expect(boundaryProblem('violation contains 1 if {\n\tcount(v) > 0\n}\n', fixture('a'), fixture('a'))).toBeUndefined();
  expect(boundaryProblem('violation contains 1 if {\n\tw > 0.15\n}\n', fixture('a'), fixture('a'))).toBeUndefined();
  // しきい値を持たないルールは対象外
  expect(boundaryProblem('violation contains 1 if {\n\tnot p.Enabled\n}\n', fixture('a'), fixture('a'))).toBeUndefined();
});

test('boundaryProblem follows the assignment to see what was counted', () => {
  const list = (n: number) => JSON.stringify({ Resources: { X: { Type: 'AWS::X::Y', Properties: { V: Array.from({ length: n }, (_, i) => `i${i}`) } } } });
  // `n := count(items)` と置いてから `n > 50` と書く形。数えたのは配列なので要素数と突き合わせる
  const counted = 'violation contains 1 if {\n\titems := flatten_list(name, "Properties.V")\n\tn := count(items)\n\tn > 50\n}\n';
  expect(boundaryProblem(counted, list(51), list(50))).toBeUndefined();
  expect(boundaryProblem(counted, list(60), list(50))).toMatch(/fail template has no 51/);
  // 同じ 51 でも、数えたのが文字列なら要素数ではなく長さを見る
  const len = 'violation contains 1 if {\n\tv := resolve(name, "Properties.V")\n\tcount(v) > 50\n}\n';
  expect(boundaryProblem(len, list(51), list(50))).toMatch(/fail template has no 51/);
  expect(boundaryProblem(len, fixture('x'.repeat(51)), fixture('x'.repeat(50)))).toBeUndefined();
  // ARN を割った断片数のガードは順序のある制約ではないので見ない
  const shape = 'violation contains 1 if {\n\tparts := split(arn, ":")\n\tcount(parts) >= 6\n}\n';
  expect(boundaryProblem(shape, fixture('a'), fixture('a'))).toBeUndefined();
});

test('boundaryProblem follows a helper call to what it counts', () => {
  const list = (n: number) => JSON.stringify({ Resources: { X: { Type: 'AWS::X::Y', Properties: { V: Array.from({ length: n }, (_, i) => `i${i}`) } } } });
  // `n := _pf_x_n(g)` のように、数えているのがヘルパー越しのこともある。定義まで辿らないと
  // 数値プールと突き合わせてしまい、境界に乗っているペアを誤検出する
  const helper = '_pf_x_n(g) := count([1 |\n\tsome it in flatten_list(g, "Properties.V")\n])\n\nviolation contains 1 if {\n\tn := _pf_x_n(name)\n\tn > 50\n}\n';
  expect(boundaryProblem(helper, list(51), list(50))).toBeUndefined();
  expect(boundaryProblem(helper, list(60), list(50))).toMatch(/fail template has no 51/);
});

test('boundaryProblem believes the type guard the rego writes', () => {
  // resolve() は文字列もマップも返す。`is_object(ev)` と書いてあるなら数えているのは
  // マップの要素数で、文字列長のプールと突き合わせてはいけない
  const rego = [
    'violation contains 1 if {',
    '\tev := resolve(name, "Properties.EnvironmentVariables")',
    '\tis_object(ev)',
    '\tcount(ev) > 2',
    '}',
    '',
  ].join('\n');
  const map = (n: number) => JSON.stringify({
    Resources: { R: { Type: 'A::B::C', Properties: { EnvironmentVariables: Object.fromEntries([...Array(n)].map((_, i) => [`K${i}`, 'v'])) } } },
  });
  expect(boundaryProblem(rego, map(3), map(2))).toBeUndefined();
  expect(boundaryProblem(rego, map(9), map(2))).toMatch(/fail template has no 3/);
});

test('boundaryProblem ignores comparisons written in comments', () => {
  // 「x <= 23 と width <= 24 だけを主張する」のような覚書はロジックではない。拾うと
  // ルールに無いしきい値を要求する。文字列の中の `#`（URL のフラグメント）は巻き込まない
  const rego = [
    '# Only the two benched maxima are claimed (x <= 23, width <= 24).',
    '_pf_x_max := {"x": 23}',
    '',
    'violation contains make_diag_full("x", "ERROR", name, "p", "m", "f",',
    '\t"https://example.com/doc.html#Percentiles") if {',
    '\tv := to_number(resolve(name, "Properties.V"))',
    '\tv > 100',
    '}',
    '',
  ].join('\n');
  const fx = (v: number) => JSON.stringify({ Resources: { R: { Type: 'A::B::C', Properties: { V: v } } } });
  expect(boundaryProblem(rego, fx(101), fx(100))).toBeUndefined();
  expect(boundaryProblem(rego, fx(200), fx(100))).toMatch(/fail template has no 101/);
});

test('boundaryProblem ignores comparisons written in the diagnostic text', () => {
  // 修正案の文面に書いた `>= 31` はロジックではない。拾うとルールに存在しない
  // しきい値を要求してしまう
  const rego = [
    'violation contains make_diag_full("x", "ERROR", name, "p",',
    '\t"retention is below 31 days",',
    '\t"Set PerformanceInsightsRetentionPeriod >= 31",',
    '\t"https://example.com") if {',
    '\tn := to_number(resolve(name, "Properties.R"))',
    '\tn < 31',
    '}',
    '',
  ].join('\n');
  const fx = (n: number) => JSON.stringify({ Resources: { X: { Type: 'AWS::X::Y', Properties: { R: n } } } });
  expect(boundaryProblem(rego, fx(30), fx(31))).toBeUndefined();
  expect(boundaryProblem(rego, fx(5), fx(31))).toMatch(/fail template has no 30/);
});

test('boundaryProblem flips a comparison the rule reads through not', () => {
  // `_ok(v) if n <= 100` を `not _ok(...)` で使うと、書かれている比較は守れている向き。
  // 裏返さずに読むと fail に 100、pass に 101 を要求してしまう（境界の反対側）
  const rego = [
    '_pf_ok(v) if {',
    '\tn := to_number(v)',
    '\tn <= 100',
    '}',
    '',
    'violation contains 1 if {',
    '\tv := resolve(name, "Properties.R")',
    '\tnot _pf_ok(v)',
    '}',
    '',
  ].join('\n');
  const fx = (n: number) => JSON.stringify({ Resources: { X: { Type: 'AWS::X::Y', Properties: { R: n } } } });
  expect(boundaryProblem(rego, fx(101), fx(100))).toBeUndefined();
  expect(boundaryProblem(rego, fx(100), fx(101))).toMatch(/fail template has no 101/);
});

test('boundaryProblem reads an index into an object as what it holds', () => {
  const fx = (n: number) => JSON.stringify({ Resources: { X: { Type: 'AWS::X::Y', Properties: { B: { k: { Content: 'x'.repeat(n) } } } } } });
  // `b[k].Content` は配列ではなく、その中の文字列。角括弧だけで配列と読むと
  // 要素数プールと突き合わせて、境界に乗っているペアを誤検出する
  const rego = 'violation contains 1 if {\n\tc := b[k].Content\n\tcount(c) > 40\n}\n';
  expect(boundaryProblem(rego, fx(41), fx(40))).toBeUndefined();
  expect(boundaryProblem(rego, fx(60), fx(40))).toMatch(/fail template has no 41/);
});

test('boundaryProblem keeps each rule body\'s assignments to itself', () => {
  const fx = (name: string, refs: number) => JSON.stringify({
    Resources: { X: { Type: 'AWS::X::Y', Properties: { Name: name, Refs: Array.from({ length: refs }, (_, i) => `r${i}`) } } },
  });
  // 同じ `n` が、片方の本体では文字列、もう片方では数えた結果。1 つの表にまとめると
  // 後から出てきたほうで上書きされ、文字列のほうが要素数プールと突き合わされる
  const rego = [
    'violation contains 1 if {',
    '\tn := b.FieldToMatch.Name',
    '\tcount(n) > 30',
    '}',
    '',
    'violation contains 2 if {',
    '\tn := count([1 | some r in refs])',
    '\tn > 50',
    '}',
    '',
  ].join('\n');
  expect(boundaryProblem(rego, fx('a'.repeat(31), 51), fx('a'.repeat(30), 50))).toBeUndefined();
  expect(boundaryProblem(rego, fx('short', 51), fx('a'.repeat(30), 50))).toMatch(/fail template has no 31/);
  expect(boundaryProblem(rego, fx('a'.repeat(31), 51), fx('a'.repeat(30), 40))).toMatch(/pass template has no 50/);
});

test('boundaryProblem measures the string the rule sees, not the escaped JSON', () => {
  // count(v) が見るのは解けた後の文字列。生のテキストのまま数えると `\"` を含む値でずれる
  const rego = 'violation contains 1 if {\n\tsome v in vals\n\tcount(v) > 20\n}\n';
  expect(boundaryProblem(rego, fixture(`"${'x'.repeat(19)}"`), fixture(`"${'x'.repeat(18)}"`))).toBeUndefined();
});

test('every fixture pair sits on the boundary, or is listed as an exception', () => {
  const exceptions = boundaryExceptions();
  const flagged = new Map<string, string>();
  for (const r of collectRules(root)) {
    const dir = path.join(root, 'rules', r.service, r.id, 'templates');
    const problem = boundaryProblem(
      r.rego,
      fs.readFileSync(path.join(dir, 'fail.template.json'), 'utf8'),
      fs.readFileSync(path.join(dir, 'pass.template.json'), 'utf8'),
    );
    if (problem) flagged.set(r.id, problem);
  }
  // 新しく緩いペアが入ってきたら、直すか例外ファイルに理由を書くまで赤いまま
  expect([...flagged].filter(([id]) => !exceptions.has(id)).map(([id, p]) => `${id}: ${p}`)).toEqual([]);
  // 直ったルールの行は残さない（#178 の残作業カウントを嘘にしないため）
  expect([...exceptions.keys()].filter((id) => !flagged.has(id))).toEqual([]);
});
