/**
 * ③ 反証工程（scripts/omission-sweep.ts）。全ルールの pass テンプレートからプロパティを 1 つずつ
 * 抜き、ルールが「省略すると落ちる」と主張していないかを調べる。主張は meta.omissionFails に
 * 実測付きで書くか、既存分なら rules/_omission-baseline.txt に載っていなければならない。
 */
import { claimKey, declaredOmissions, omissionClaims, omissionProblems, propertyPaths, readOmissionBaseline, without } from '../scripts/omission-sweep';

test('mutants drop one property at a time, down to three levels, through the first array element', () => {
  const props = { A: 1, B: { C: 2, D: [{ E: 3 }] }, F: { 'Fn::GetAtt': ['X', 'Y'] } };
  expect(propertyPaths(props)).toEqual(['A', 'B', 'B.C', 'B.D', 'B.D.0.E', 'F']);
  expect(without(props, 'B.D.0.E')).toEqual({ A: 1, B: { C: 2, D: [{}] }, F: { 'Fn::GetAtt': ['X', 'Y'] } });
  expect(props.B.D[0]).toEqual({ E: 3 });
  expect(claimKey('AWS::X::Y', 'B.D.0.E')).toBe('AWS::X::Y.B.D.*.E');
});

test('the ratchet: undeclared claims, stale baseline lines and stale declarations all fail', () => {
  const claims = [{ rule: 'pf-a', key: 'T.P' }, { rule: 'pf-b', key: 'T.Q' }];
  expect(omissionProblems(claims, new Set(['pf-a T.P']), new Set(['pf-b T.Q']))).toEqual([]);
  expect(omissionProblems(claims, new Set(), new Set(['pf-b T.Q']))[0]).toMatch(/pf-a fires when T.P is omitted/);
  expect(omissionProblems(claims, new Set(['pf-a T.P', 'pf-c T.R']), new Set(['pf-b T.Q', 'pf-b T.Z'])).sort()).toEqual([
    expect.stringMatching(/meta.omissionFails of pf-c/),
    expect.stringMatching(/'pf-b T.Z' is no longer claimed/),
  ].sort());
});

test('no rule claims that omitting a property fails the deploy without evidence', () => {
  expect(omissionProblems(omissionClaims(), declaredOmissions(), readOmissionBaseline())).toEqual([]);
}, 30 * 60 * 1000);
