/**
 * Condition の三値評価（src/private/conditions.ts）。証明できた false だけがリソースを外す。
 */
import { inactiveResources, specializeTemplate } from '../src/private/conditions';

const sub = (condition: string) => ({ Type: 'AWS::SNS::Subscription', Condition: condition, Properties: {} });

function inactive(t: { Parameters?: object; Conditions: object; Mappings?: object }, pseudo = { region: 'us-east-1', accountId: '123456789012' }): string[] {
  const resources = Object.fromEntries(Object.keys(t.Conditions).map((c) => [`R${c}`, sub(c)]));
  return [...inactiveResources({ ...t, Resources: resources }, pseudo)].sort();
}

describe('inactiveResources', () => {
  test('issue #408: an empty slot of a CommaDelimitedList default switches the resource off', () => {
    expect(inactive({
      Parameters: { Emails: { Type: 'CommaDelimitedList', Default: 'admin@example.com,' } },
      Conditions: {
        Has0: { 'Fn::Not': [{ 'Fn::Equals': [{ 'Fn::Select': [0, { Ref: 'Emails' }] }, ''] }] },
        Has1: { 'Fn::Not': [{ 'Fn::Equals': [{ 'Fn::Select': [1, { Ref: 'Emails' }] }, ''] }] },
        // 範囲外の Select は CloudFormation ではエラーだが、ここでは判定しない（不明）
        Has2: { 'Fn::Not': [{ 'Fn::Equals': [{ 'Fn::Select': [2, { Ref: 'Emails' }] }, ''] }] },
      },
    })).toEqual(['RHas1']);
  });

  test('a parameter without a default, or an SSM parameter type, is unknown and keeps the resource', () => {
    expect(inactive({
      Parameters: {
        NoDefault: { Type: 'String' },
        Ssm: { Type: 'AWS::SSM::Parameter::Value<String>', Default: '/x' },
      },
      Conditions: {
        A: { 'Fn::Equals': [{ Ref: 'NoDefault' }, 'x'] },
        B: { 'Fn::Equals': [{ Ref: 'Ssm' }, 'x'] },
        C: { 'Fn::Not': [{ 'Fn::Equals': [{ Ref: 'NoDefault' }, 'x'] }] },
      },
    })).toEqual([]);
  });

  test('And / Or are short-circuited on a proven operand even when another is unknown', () => {
    expect(inactive({
      Parameters: { Env: { Type: 'String', Default: 'dev' }, X: { Type: 'String' } },
      Conditions: {
        IsProd: { 'Fn::Equals': [{ Ref: 'Env' }, 'prod'] },
        AndFalse: { 'Fn::And': [{ Condition: 'IsProd' }, { 'Fn::Equals': [{ Ref: 'X' }, 'a'] }] },
        AndUnknown: { 'Fn::And': [{ 'Fn::Not': [{ Condition: 'IsProd' }] }, { 'Fn::Equals': [{ Ref: 'X' }, 'a'] }] },
        OrTrue: { 'Fn::Or': [{ 'Fn::Not': [{ Condition: 'IsProd' }] }, { 'Fn::Equals': [{ Ref: 'X' }, 'a'] }] },
        OrUnknown: { 'Fn::Or': [{ Condition: 'IsProd' }, { 'Fn::Equals': [{ Ref: 'X' }, 'a'] }] },
      },
    })).toEqual(['RAndFalse', 'RIsProd']);
  });

  test('pseudo parameters count only when the stack environment is concrete', () => {
    const t = {
      Conditions: {
        // CDK の CDKMetadataAvailable と同じ形
        CnOnly: { 'Fn::Or': [{ 'Fn::Equals': [{ Ref: 'AWS::Region' }, 'cn-north-1'] }, { 'Fn::Equals': [{ Ref: 'AWS::Region' }, 'cn-northwest-1'] }] },
        Partition: { 'Fn::Equals': [{ Ref: 'AWS::Partition' }, 'aws-cn'] },
        Account: { 'Fn::Equals': [{ Ref: 'AWS::AccountId' }, '999999999999'] },
      },
    };
    expect(inactive(t)).toEqual(['RAccount', 'RCnOnly', 'RPartition']);
    expect(inactive(t, { region: '${Token[AWS.Region.1]}', accountId: '${Token[AWS.AccountId.2]}' })).toEqual([]);
  });

  test('Join, Split and FindInMap are evaluated; unmodelled intrinsics are unknown', () => {
    expect(inactive({
      Parameters: { Stage: { Type: 'String', Default: 'dev' } },
      Mappings: { M: { dev: { On: 'no' } } },
      Conditions: {
        Joined: { 'Fn::Equals': [{ 'Fn::Join': ['-', ['a', { Ref: 'Stage' }]] }, 'a-prod'] },
        Split: { 'Fn::Equals': [{ 'Fn::Select': [1, { 'Fn::Split': [',', 'x,'] }] }, 'y'] },
        Mapped: { 'Fn::Equals': [{ 'Fn::FindInMap': ['M', { Ref: 'Stage' }, 'On'] }, 'yes'] },
        Sub: { 'Fn::Equals': [{ 'Fn::Sub': '${Stage}' }, 'prod'] },
        GetAtt: { 'Fn::Equals': [{ 'Fn::GetAtt': ['X', 'Y'] }, 'prod'] },
      },
    })).toEqual(['RJoined', 'RMapped', 'RSplit']);
  });

  test('a numeric default compares as its string form, as CloudFormation does', () => {
    expect(inactive({
      Parameters: { N: { Type: 'Number', Default: 3 } },
      Conditions: { Three: { 'Fn::Equals': [{ Ref: 'N' }, '3'] }, Four: { 'Fn::Equals': [{ Ref: 'N' }, 4] } },
    })).toEqual(['RFour']);
  });

  test('a missing or cyclic condition is unknown, and so is a malformed template', () => {
    expect(inactive({ Conditions: { A: { Condition: 'B' }, B: { Condition: 'A' }, C: { Condition: 'Nope' } } })).toEqual([]);
    expect([...inactiveResources(null)]).toEqual([]);
    expect([...inactiveResources({ Resources: { R: { Type: 'X', Condition: 'Missing' } } })]).toEqual([]);
  });
});

describe('specializeTemplate', () => {
  const params = { Parameters: { Flag: { Type: 'String', Default: 'off' }, Free: { Type: 'String' } } };
  const conditions = {
    On: { 'Fn::Equals': [{ Ref: 'Flag' }, 'on'] },
    Off: { 'Fn::Equals': [{ Ref: 'Flag' }, 'off'] },
    Maybe: { 'Fn::Equals': [{ Ref: 'Free' }, 'x'] },
  };

  test('takes the decided Fn::If branch, drops a taken AWS::NoValue, keeps an undecided Fn::If', () => {
    const out = specializeTemplate({
      ...params,
      Conditions: conditions,
      Resources: {
        R: {
          Type: 'AWS::SNS::Topic',
          Properties: {
            A: { 'Fn::If': ['On', 'bad', 'good'] },
            B: { 'Fn::If': ['On', 'x', { Ref: 'AWS::NoValue' }] },
            C: [{ 'Fn::If': ['Off', { Ref: 'AWS::NoValue' }, 'y'] }, 'z'],
            D: { 'Fn::If': ['Maybe', 1, 2] },
          },
        },
      },
    }) as any;
    expect(out.Resources.R.Properties).toEqual({ A: 'good', C: ['z'], D: { 'Fn::If': ['Maybe', 1, 2] } });
  });

  test('removes switched-off resources and outputs, and the DependsOn entries that point at them', () => {
    const out = specializeTemplate({
      ...params,
      Conditions: conditions,
      Resources: {
        Gone: { Type: 'AWS::SNS::Topic', Condition: 'On' },
        Kept: { Type: 'AWS::SNS::Topic', Condition: 'Maybe', DependsOn: ['Gone', 'Other'] },
        Other: { Type: 'AWS::SNS::Topic', DependsOn: 'Gone' },
      },
      Outputs: { O1: { Condition: 'On', Value: { Ref: 'Gone' } }, O2: { Value: { 'Fn::If': ['On', { Ref: 'Gone' }, 'none'] } } },
    }) as any;
    expect(Object.keys(out.Resources)).toEqual(['Kept', 'Other']);
    expect(out.Resources.Kept.DependsOn).toEqual(['Other']);
    expect(out.Resources.Other.DependsOn).toBeUndefined();
    expect(out.Outputs).toEqual({ O2: { Value: 'none' } });
  });

  test('a template with nothing decided is left alone', () => {
    expect(specializeTemplate({
      ...params,
      Conditions: conditions,
      Resources: { R: { Type: 'AWS::SNS::Topic', Condition: 'Maybe', Properties: { A: { 'Fn::If': ['Maybe', 1, 2] } } } },
    })).toBeUndefined();
  });
});
