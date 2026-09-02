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
import { deployEnvironmentModule, loadEngine } from '../src/private/enforce';
import { BUNDLED_RULES } from '../src/rules.generated';

interface Diagnostic {
  ruleId: string;
  severity: string;
  message: string;
  source?: string;
}

const engine = loadEngine();

/** フィクスチャ評価時のデプロイリージョン（deploy_region 注入のハーネス既定）。 */
const HARNESS_REGION = 'us-east-1';

// エンジン初期化（WASM）と評価は重いので、リージョンごとに 1 エンジンに全ルールを
// 載せてキャッシュし、フィクスチャの診断結果も共有する。本番の enforce プラグインと
// 同じ deployEnvironmentModule を注入する（ローダー契約のカップリングテストを兼ねる）。
const engineCache = new Map<string, any>();
function engineInstance(region?: string): any {
  const key = region ?? '';
  if (!engineCache.has(key)) {
    const customRules = BUNDLED_RULES.map((r) => ({ name: r.id, content: r.rego }));
    if (region) customRules.push(deployEnvironmentModule(region));
    engineCache.set(key, new engine.RegoEngine({ customRules }));
  }
  return engineCache.get(key);
}

const diagCache = new Map<string, Diagnostic[]>();
function diagnose(templateFile: string): Diagnostic[] {
  if (!diagCache.has(templateFile)) {
    const report = engineInstance(HARNESS_REGION).validateDetailed(new engine.TemplateFile(templateFile), {
      pseudoParameterOverrides: { accountId: '123456789012', region: HARNESS_REGION },
    });
    diagCache.set(templateFile, (report.diagnostics ?? []) as Diagnostic[]);
  }
  return diagCache.get(templateFile)!;
}

/**
 * 一時ファイルに書いて評価する。region を渡すと擬似パラメータ解決と
 * deploy_region 注入の両方を有効にする（省略時はどちらも無し＝リージョン不明の挙動）。
 */
function diagnoseTemplate(tpl: unknown, region?: string): Diagnostic[] {
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

/**
 * CloudFront ルールのうち、fail フィクスチャ 1 枚では踏めない分岐と、
 * このパック固有の武器（デプロイ先リージョンの解決）を直接固定するテスト。
 */
describe('cloudfront rules', () => {
  const originS3 = {
    Id: 'origin1',
    DomainName: 'bucket.s3.us-east-1.amazonaws.com',
    S3OriginConfig: { OriginAccessIdentity: '' },
  };
  const distribution = (config: Record<string, unknown>) => ({
    Resources: {
      Dist: {
        Type: 'AWS::CloudFront::Distribution',
        Properties: {
          DistributionConfig: {
            Enabled: true,
            Origins: [originS3],
            DefaultCacheBehavior: {
              TargetOriginId: 'origin1',
              ViewerProtocolPolicy: 'allow-all',
              ForwardedValues: { QueryString: false },
            },
            ...config,
          },
        },
      },
    },
  });
  const edgeAssociation = (arn: unknown) => distribution({
    DefaultCacheBehavior: {
      TargetOriginId: 'origin1',
      ViewerProtocolPolicy: 'allow-all',
      ForwardedValues: { QueryString: false },
      LambdaFunctionAssociations: [{ EventType: 'viewer-request', LambdaFunctionARN: arn }],
    },
  });
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);

  describe('pf-cloudfront-edge-lambda-region', () => {
    // このパックにしか書けない検査の本体: CDK が組み立てる ARN は
    // {"Ref": "AWS::Region"} 入りの Fn::Join なので、L2 も cfn-lint も
    // リージョンを知りようがない。プラグイン経由で渡る実リージョンで解決する。
    const joinedArn = {
      'Fn::Join': ['', [
        'arn:', { Ref: 'AWS::Partition' }, ':lambda:', { Ref: 'AWS::Region' }, ':',
        { Ref: 'AWS::AccountId' }, ':function:edge-auth:3',
      ]],
    };

    test('resolves AWS::Region and fires when the stack is not in us-east-1', () => {
      const ds = diagnoseTemplate(edgeAssociation(joinedArn), 'ap-northeast-1');
      const mine = ds.filter((d) => d.ruleId === 'pf-cloudfront-edge-lambda-region');
      expect(mine).toHaveLength(1);
      expect(mine[0].message).toContain('ap-northeast-1');
    });

    test('the same template is clean when the stack is in us-east-1', () => {
      const ds = diagnoseTemplate(edgeAssociation(joinedArn), 'us-east-1');
      expect(ids(ds)).not.toContain('pf-cloudfront-edge-lambda-region');
    });

    test('an ARN that stays unresolved (cross-stack GetAtt) is skipped, not guessed at', () => {
      const tpl: any = edgeAssociation({ 'Fn::GetAtt': ['Ver', 'FunctionArn'] });
      tpl.Resources.Ver = {
        Type: 'AWS::Lambda::Version',
        Properties: { FunctionName: 'edge-auth' },
      };
      expect(ids(diagnoseTemplate(tpl, 'ap-northeast-1'))).toHaveLength(0);
    });

    test('fires on an additional cache behavior, not just the default one', () => {
      const ds = diagnoseTemplate(distribution({
        CacheBehaviors: [{
          PathPattern: '/api/*',
          TargetOriginId: 'origin1',
          ViewerProtocolPolicy: 'allow-all',
          ForwardedValues: { QueryString: false },
          LambdaFunctionAssociations: [{
            EventType: 'origin-request',
            LambdaFunctionARN: 'arn:aws:lambda:eu-west-1:123456789012:function:edge-auth:3',
          }],
        }],
      }), 'us-east-1');
      const mine = ds.filter((d) => d.ruleId === 'pf-cloudfront-edge-lambda-region');
      expect(mine).toHaveLength(1);
      expect(mine[0].message).toContain('eu-west-1');
    });
  });

  describe('pf-cloudfront-edge-lambda-version', () => {
    test('rejects an alias qualifier', () => {
      const ds = diagnoseTemplate(edgeAssociation('arn:aws:lambda:us-east-1:123456789012:function:edge-auth:live'));
      const mine = ds.filter((d) => d.ruleId === 'pf-cloudfront-edge-lambda-version');
      expect(mine).toHaveLength(1);
      expect(mine[0].message).toContain('live');
    });

    test('rejects $LATEST', () => {
      const ds = diagnoseTemplate(edgeAssociation('arn:aws:lambda:us-east-1:123456789012:function:edge-auth:$LATEST'));
      expect(ids(ds)).toContain('pf-cloudfront-edge-lambda-version');
    });

    test('accepts a numeric version qualifier', () => {
      const ds = diagnoseTemplate(edgeAssociation('arn:aws:lambda:us-east-1:123456789012:function:edge-auth:12'));
      expect(ids(ds)).toHaveLength(0);
    });
  });

  describe('pf-cloudfront-cached-methods-subset', () => {
    test('fires when AllowedMethods is omitted and CachedMethods exceeds the GET/HEAD default', () => {
      const ds = diagnoseTemplate(distribution({
        DefaultCacheBehavior: {
          TargetOriginId: 'origin1',
          ViewerProtocolPolicy: 'allow-all',
          ForwardedValues: { QueryString: false },
          CachedMethods: ['GET', 'HEAD', 'OPTIONS'],
        },
      }));
      expect(ids(ds)).toContain('pf-cloudfront-cached-methods-subset');
    });
  });

  describe('pf-cloudfront-wafv2-webacl-scope', () => {
    test('leaves a WAF Classic web ACL id alone', () => {
      const ds = diagnoseTemplate(distribution({ WebACLId: 'a1b2c3d4-5678-90ab-cdef-EXAMPLE11111' }));
      expect(ids(ds)).toHaveLength(0);
    });

    // CloudFront checks the ARN's scope segment, not its region, so a REGIONAL
    // web ACL that happens to live in us-east-1 is rejected just the same.
    test('fires on a REGIONAL web ACL created in us-east-1', () => {
      const ds = diagnoseTemplate(distribution({
        WebACLId: 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/app/1a2b3c4d-5e6f-7890-abcd-ef1234567890',
      }));
      expect(ids(ds)).toContain('pf-cloudfront-wafv2-webacl-scope');
    });
  });
});

describe('route53 rules', () => {
  const record = (props: Record<string, unknown>) => ({
    Resources: {
      Rec: {
        Type: 'AWS::Route53::RecordSet',
        Properties: {
          HostedZoneId: 'Z1234567890ABC',
          Name: 'www.example.org.',
          Type: 'A',
          ...props,
        },
      },
    },
  });
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);

  describe('pf-route53-apex-cname', () => {
    // E3023 は HostedZoneName リテラル形しか見ない。CDK L2 が吐く
    // HostedZoneId {Ref} 形はこのルールだけが apex を判定できる。
    const zoneAndCname = (recName: string) => ({
      Resources: {
        Zone: { Type: 'AWS::Route53::HostedZone', Properties: { Name: 'example.org.' } },
        Rec: {
          Type: 'AWS::Route53::RecordSet',
          Properties: {
            HostedZoneId: { Ref: 'Zone' },
            Name: recName,
            Type: 'CNAME',
            ResourceRecords: ['target.example.net.'],
            TTL: '300',
          },
        },
      },
    });

    test('normalizes the trailing dot when comparing names', () => {
      const ds = diagnoseTemplate(zoneAndCname('example.org'));
      expect(ids(ds)).toContain('pf-route53-apex-cname');
    });

    test('stays silent when the zone lives outside the template', () => {
      const ds = diagnoseTemplate(record({ Type: 'CNAME', ResourceRecords: ['target.example.net.'], TTL: '300' }));
      expect(ids(ds)).toHaveLength(0);
    });
  });

  describe('pf-route53-set-identifier-pairing', () => {
    test('fires when SetIdentifier has no routing policy', () => {
      const ds = diagnoseTemplate(record({ ResourceRecords: ['192.0.2.1'], TTL: '300', SetIdentifier: 'one' }));
      expect(ids(ds)).toContain('pf-route53-set-identifier-pairing');
    });

    test('MultiValueAnswer: false does not count as a routing policy', () => {
      const ds = diagnoseTemplate(record({
        ResourceRecords: ['192.0.2.1'], TTL: '300', SetIdentifier: 'one', MultiValueAnswer: false,
      }));
      expect(ids(ds)).toContain('pf-route53-set-identifier-pairing');
      expect(ids(ds)).not.toContain('pf-route53-routing-policy-exclusive');
    });
  });

  describe('pf-route53-record-type-routing-policy', () => {
    test('fires on a multivalue CNAME', () => {
      const ds = diagnoseTemplate(record({
        Type: 'CNAME',
        ResourceRecords: ['target.example.net.'],
        TTL: '300',
        MultiValueAnswer: true,
        SetIdentifier: 'one',
      }));
      expect(ids(ds)).toContain('pf-route53-record-type-routing-policy');
    });
  });

  describe('pf-route53-record-value-source', () => {
    test('fires when TTL is present but ResourceRecords is missing', () => {
      const ds = diagnoseTemplate(record({ TTL: '300' }));
      expect(ids(ds)).toContain('pf-route53-record-value-source');
    });

    test('fires when ResourceRecords is present but TTL is missing', () => {
      const ds = diagnoseTemplate(record({ ResourceRecords: ['192.0.2.1'] }));
      expect(ids(ds)).toContain('pf-route53-record-value-source');
    });

    test('a TTL supplied through a template parameter is treated as present', () => {
      const ds = diagnoseTemplate({
        Parameters: { Ttl: { Type: 'String', Default: '300' } },
        ...record({ ResourceRecords: ['192.0.2.1'], TTL: { Ref: 'Ttl' } }),
      });
      expect(ids(ds)).not.toContain('pf-route53-record-value-source');
    });
  });

  describe('pf-route53-alias-cloudfront-zone-id', () => {
    test('normalizes a trailing dot on the DNS name', () => {
      const ds = diagnoseTemplate(record({
        AliasTarget: { DNSName: 'd111111abcdef8.cloudfront.net.', HostedZoneId: 'Z14GRHDCWA56QT' },
      }));
      expect(ids(ds)).toContain('pf-route53-alias-cloudfront-zone-id');
    });

    test('leaves non-CloudFront alias targets alone', () => {
      const ds = diagnoseTemplate(record({
        AliasTarget: { DNSName: 'my-lb-123.ap-northeast-1.elb.amazonaws.com', HostedZoneId: 'Z14GRHDCWA56QT' },
      }));
      expect(ids(ds)).toHaveLength(0);
    });
  });
});

describe('dynamodb rules', () => {
  const table = (props: Record<string, unknown>) => ({
    Resources: { T: { Type: 'AWS::DynamoDB::Table', Properties: props } },
  });
  const AD = (...names: string[]) => names.map((n) => ({ AttributeName: n, AttributeType: 'S' }));
  const KS = (...pairs: [string, string][]) => pairs.map(([n, t]) => ({ AttributeName: n, KeyType: t }));
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);

  describe('pf-dynamodb-key-schema-shape', () => {
    test('fires on two HASH elements', () => {
      const ds = diagnoseTemplate(table({
        AttributeDefinitions: AD('pk', 'sk'), KeySchema: KS(['pk', 'HASH'], ['sk', 'HASH']), BillingMode: 'PAY_PER_REQUEST',
      }));
      expect(ids(ds)).toContain('pf-dynamodb-key-schema-shape');
    });

    test('fires on three key elements', () => {
      const ds = diagnoseTemplate(table({
        AttributeDefinitions: AD('pk', 'sk', 'x'),
        KeySchema: KS(['pk', 'HASH'], ['sk', 'RANGE'], ['x', 'RANGE']),
        BillingMode: 'PAY_PER_REQUEST',
      }));
      expect(ids(ds)).toContain('pf-dynamodb-key-schema-shape');
    });
  });

  describe('pf-dynamodb-lsi-shape', () => {
    test('fires when the LSI hash key differs from the table hash key', () => {
      const ds = diagnoseTemplate(table({
        AttributeDefinitions: AD('pk', 'sk', 'other'),
        KeySchema: KS(['pk', 'HASH'], ['sk', 'RANGE']),
        BillingMode: 'PAY_PER_REQUEST',
        LocalSecondaryIndexes: [{ IndexName: 'lsi1', KeySchema: KS(['other', 'HASH'], ['sk', 'RANGE']), Projection: { ProjectionType: 'ALL' } }],
      }));
      expect(ids(ds)).toContain('pf-dynamodb-lsi-shape');
    });
  });

  describe('pf-dynamodb-attribute-definitions-usage', () => {
    test('stays silent when a key attribute name is unresolvable', () => {
      const ds = diagnoseTemplate(table({
        AttributeDefinitions: AD('pk', 'maybeUsed'),
        KeySchema: [{ AttributeName: { 'Fn::ImportValue': 'SharedKeyName' }, KeyType: 'HASH' }],
        BillingMode: 'PAY_PER_REQUEST',
      }));
      expect(ids(ds)).not.toContain('pf-dynamodb-attribute-definitions-usage');
    });

    test('counts an attribute used only by an LSI as used', () => {
      const ds = diagnoseTemplate(table({
        AttributeDefinitions: AD('pk', 'sk', 'alt'),
        KeySchema: KS(['pk', 'HASH'], ['sk', 'RANGE']),
        BillingMode: 'PAY_PER_REQUEST',
        LocalSecondaryIndexes: [{ IndexName: 'lsi1', KeySchema: KS(['pk', 'HASH'], ['alt', 'RANGE']), Projection: { ProjectionType: 'ALL' } }],
      }));
      expect(ids(ds)).toHaveLength(0);
    });
  });

  describe('pf-dynamodb-gsi-billing-throughput', () => {
    test('fires when a PROVISIONED-by-default table has a GSI without throughput', () => {
      const ds = diagnoseTemplate(table({
        AttributeDefinitions: AD('pk', 'g'),
        KeySchema: KS(['pk', 'HASH']),
        ProvisionedThroughput: { ReadCapacityUnits: 1, WriteCapacityUnits: 1 },
        GlobalSecondaryIndexes: [{ IndexName: 'gsi1', KeySchema: KS(['g', 'HASH']), Projection: { ProjectionType: 'ALL' } }],
      }));
      expect(ids(ds)).toContain('pf-dynamodb-gsi-billing-throughput');
    });
  });

  describe('pf-dynamodb-gsi-projection-nonkey', () => {
    test('fires on ALL with NonKeyAttributes', () => {
      const ds = diagnoseTemplate(table({
        AttributeDefinitions: AD('pk', 'g'),
        KeySchema: KS(['pk', 'HASH']),
        BillingMode: 'PAY_PER_REQUEST',
        GlobalSecondaryIndexes: [{ IndexName: 'gsi1', KeySchema: KS(['g', 'HASH']), Projection: { ProjectionType: 'ALL', NonKeyAttributes: ['extra'] } }],
      }));
      expect(ids(ds)).toContain('pf-dynamodb-gsi-projection-nonkey');
    });
  });

  describe('pf-dynamodb-duplicate-index-name', () => {
    test('fires on duplicate LSI names', () => {
      const ds = diagnoseTemplate(table({
        AttributeDefinitions: AD('pk', 'sk', 'a', 'b'),
        KeySchema: KS(['pk', 'HASH'], ['sk', 'RANGE']),
        BillingMode: 'PAY_PER_REQUEST',
        LocalSecondaryIndexes: [
          { IndexName: 'lsi1', KeySchema: KS(['pk', 'HASH'], ['a', 'RANGE']), Projection: { ProjectionType: 'ALL' } },
          { IndexName: 'lsi1', KeySchema: KS(['pk', 'HASH'], ['b', 'RANGE']), Projection: { ProjectionType: 'ALL' } },
        ],
      }));
      expect(ids(ds)).toContain('pf-dynamodb-duplicate-index-name');
    });
  });
});

describe('deploy_region rules', () => {
  const globalTable = (region: string) => ({
    Resources: {
      GT: {
        Type: 'AWS::DynamoDB::GlobalTable',
        Properties: {
          AttributeDefinitions: [{ AttributeName: 'pk', AttributeType: 'S' }],
          KeySchema: [{ AttributeName: 'pk', KeyType: 'HASH' }],
          BillingMode: 'PAY_PER_REQUEST',
          StreamSpecification: { StreamViewType: 'NEW_AND_OLD_IMAGES' },
          Replicas: [{ Region: region }],
        },
      },
    },
  });
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);

  test('replica rule fires only when the deploy region is missing from Replicas', () => {
    expect(ids(diagnoseTemplate(globalTable('us-east-1'), 'ap-northeast-1')))
      .toContain('pf-dynamodb-global-table-replica-region');
    expect(ids(diagnoseTemplate(globalTable('ap-northeast-1'), 'ap-northeast-1')))
      .toHaveLength(0);
  });

  // deploy_region 未注入（リージョン不明）ではリージョン依存ルールは沈黙する。
  // data 参照が undefined に評価されるだけでコンパイルは通ることの回帰テスト。
  test('both rules stay silent without deploy_region injection', () => {
    const ds = diagnoseTemplate(globalTable('us-east-1'));
    expect(ids(ds)).toHaveLength(0);
    const kinesis = {
      Resources: {
        T: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            AttributeDefinitions: [{ AttributeName: 'pk', AttributeType: 'S' }],
            KeySchema: [{ AttributeName: 'pk', KeyType: 'HASH' }],
            BillingMode: 'PAY_PER_REQUEST',
            KinesisStreamSpecification: { StreamArn: 'arn:aws:kinesis:eu-west-1:123456789012:stream/x' },
          },
        },
      },
    };
    expect(ids(diagnoseTemplate(kinesis))).toHaveLength(0);
  });

  test('kinesis rule compares the ARN region against the deploy region', () => {
    const kinesis = (arnRegion: string) => ({
      Resources: {
        T: {
          Type: 'AWS::DynamoDB::Table',
          Properties: {
            AttributeDefinitions: [{ AttributeName: 'pk', AttributeType: 'S' }],
            KeySchema: [{ AttributeName: 'pk', KeyType: 'HASH' }],
            BillingMode: 'PAY_PER_REQUEST',
            KinesisStreamSpecification: { StreamArn: `arn:aws:kinesis:${arnRegion}:123456789012:stream/x` },
          },
        },
      },
    });
    expect(ids(diagnoseTemplate(kinesis('us-east-1'), 'ap-northeast-1')))
      .toContain('pf-dynamodb-kinesis-stream-region');
    expect(ids(diagnoseTemplate(kinesis('ap-northeast-1'), 'ap-northeast-1')))
      .toHaveLength(0);
  });

  test('replica rule skips when a replica region is unresolvable', () => {
    const t = {
      Resources: {
        GT: {
          Type: 'AWS::DynamoDB::GlobalTable',
          Properties: {
            AttributeDefinitions: [{ AttributeName: 'pk', AttributeType: 'S' }],
            KeySchema: [{ AttributeName: 'pk', KeyType: 'HASH' }],
            BillingMode: 'PAY_PER_REQUEST',
            StreamSpecification: { StreamViewType: 'NEW_AND_OLD_IMAGES' },
            Replicas: [{ Region: { 'Fn::ImportValue': 'ReplicaRegion' } }],
          },
        },
      },
    };
    expect(ids(diagnoseTemplate(t, 'ap-northeast-1'))).toHaveLength(0);
  });
});
