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

describe('ecs task definition rules', () => {
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);

  const td = (props: Record<string, unknown>, parameters?: Record<string, unknown>) => ({
    ...(parameters ? { Parameters: parameters } : {}),
    Resources: { TD: { Type: 'AWS::ECS::TaskDefinition', Properties: props } },
  });
  const APP = { Name: 'app', Image: 'public.ecr.aws/nginx/nginx:latest', Essential: true };

  describe('pf-ecs-container-memory-required', () => {
    test('skips when task Memory is present but unresolvable (Ref without default)', () => {
      // `not resolve(...)` would fire here — the input.resources absence proof must not
      const t = td(
        { Memory: { Ref: 'MemParam' }, ContainerDefinitions: [APP] },
        { MemParam: { Type: 'String' } },
      );
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-ecs-fargate-task-cpu-memory', () => {
    test('fires once per missing task-level setting', () => {
      const t = td({
        RequiresCompatibilities: ['FARGATE'],
        NetworkMode: 'awsvpc',
        ContainerDefinitions: [{ ...APP, Memory: 512 }],
      });
      const got = ids(diagnoseTemplate(t));
      expect(got).toHaveLength(2);
      expect(new Set(got)).toEqual(new Set(['pf-ecs-fargate-task-cpu-memory']));
    });

    test('skips when Cpu and Memory are present but unresolvable', () => {
      const t = td(
        {
          RequiresCompatibilities: ['FARGATE'],
          NetworkMode: 'awsvpc',
          Cpu: { Ref: 'CpuParam' },
          Memory: { Ref: 'MemParam' },
          ContainerDefinitions: [{ ...APP, Memory: 512 }],
        },
        { CpuParam: { Type: 'String' }, MemParam: { Type: 'String' } },
      );
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-ecs-fargate-network-mode', () => {
    test('not-set block skips when NetworkMode is a Ref without default', () => {
      const t = td(
        {
          RequiresCompatibilities: ['FARGATE'],
          NetworkMode: { Ref: 'NmParam' },
          Cpu: '256',
          Memory: '512',
          ContainerDefinitions: [APP],
        },
        { NmParam: { Type: 'String' } },
      );
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-ecs-container-definitions-empty', () => {
    test('fires when ContainerDefinitions is absent entirely (bench e06b)', () => {
      const t = td({ Cpu: '256' });
      expect(ids(diagnoseTemplate(t))).toContain('pf-ecs-container-definitions-empty');
    });
  });

  describe('pf-ecs-essential-container', () => {
    test('skips when one Essential is unresolvable — absence of an essential container is unproven', () => {
      const t = td(
        {
          ContainerDefinitions: [
            { ...APP, Essential: false, Memory: 256 },
            { Name: 'b', Image: 'public.ecr.aws/nginx/nginx:latest', Essential: { Ref: 'EssParam' }, Memory: 256 },
          ],
        },
        { EssParam: { Type: 'String' } },
      );
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-ecs-duplicate-container-names', () => {
    test('skips Ref-valued names — only literal duplicates are provable', () => {
      const t = td(
        {
          ContainerDefinitions: [
            { Name: { Ref: 'NameParam' }, Image: 'x', Essential: true, Memory: 256 },
            { Name: { Ref: 'NameParam' }, Image: 'x', Essential: false, Memory: 256 },
          ],
        },
        { NameParam: { Type: 'String' } },
      );
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-ecs-container-memory-over-task', () => {
    test('skips when the task Memory is unresolvable', () => {
      const t = td(
        {
          Memory: { Ref: 'MemParam' },
          ContainerDefinitions: [{ ...APP, Memory: 1024 }],
        },
        { MemParam: { Type: 'String' } },
      );
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-ecs-container-memory-reservation', () => {
    test('coerces string-typed numbers before comparing', () => {
      const t = td({ ContainerDefinitions: [{ ...APP, Memory: '256', MemoryReservation: '512' }] });
      expect(ids(diagnoseTemplate(t))).toContain('pf-ecs-container-memory-reservation');
    });
  });
});

describe('s3 bucket rules', () => {
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);

  const bucket = (props: Record<string, unknown>) => ({
    Resources: { B: { Type: 'AWS::S3::Bucket', Properties: props } },
  });

  describe('pf-s3-replication-requires-versioning', () => {
    test('skips when Status is present but unresolvable (regression: fired before the input.resources fix)', () => {
      const t = {
        Parameters: { V: { Type: 'String' } },
        Resources: {
          B: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              VersioningConfiguration: { Status: { Ref: 'V' } },
              ReplicationConfiguration: {
                Role: 'arn:aws:iam::123456789012:role/repl',
                Rules: [{ Status: 'Enabled', Destination: { Bucket: 'arn:aws:s3:::elsewhere' } }],
              },
            },
          },
        },
      };
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });

    test('still fires on a literal Suspended', () => {
      const t = bucket({
        VersioningConfiguration: { Status: 'Suspended' },
        ReplicationConfiguration: {
          Role: 'arn:aws:iam::123456789012:role/repl',
          Rules: [{ Status: 'Enabled', Destination: { Bucket: 'arn:aws:s3:::elsewhere' } }],
        },
      });
      expect(ids(diagnoseTemplate(t))).toContain('pf-s3-replication-requires-versioning');
    });
  });

  describe('pf-s3-replication-dest-versioning', () => {
    test('skips an external destination ARN — the target bucket is not in the template', () => {
      const t = {
        Resources: {
          Src: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              VersioningConfiguration: { Status: 'Enabled' },
              ReplicationConfiguration: {
                Role: 'arn:aws:iam::123456789012:role/repl',
                Rules: [{ Status: 'Enabled', Destination: { Bucket: 'arn:aws:s3:::external-bucket' } }],
              },
            },
          },
        },
      };
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });

    test('fires when the in-template destination suspends versioning', () => {
      const t = {
        Resources: {
          Dest: { Type: 'AWS::S3::Bucket', Properties: { VersioningConfiguration: { Status: 'Suspended' } } },
          Src: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              VersioningConfiguration: { Status: 'Enabled' },
              ReplicationConfiguration: {
                Role: 'arn:aws:iam::123456789012:role/repl',
                Rules: [{ Status: 'Enabled', Destination: { Bucket: { 'Fn::GetAtt': ['Dest', 'Arn'] } } }],
              },
            },
          },
        },
      };
      expect(ids(diagnoseTemplate(t))).toContain('pf-s3-replication-dest-versioning');
    });
  });

  describe('pf-s3-notification-overlapping-filters', () => {
    const notif = (configs: unknown[]) => bucket({ NotificationConfiguration: { QueueConfigurations: configs } });
    const q = 'arn:aws:sqs:ap-northeast-1:123456789012:q';

    test('a wildcard event overlaps its specific form', () => {
      const t = notif([
        { Event: 's3:ObjectCreated:*', Queue: q, Filter: { S3Key: { Rules: [{ Name: 'prefix', Value: 'a/' }] } } },
        { Event: 's3:ObjectCreated:Put', Queue: q, Filter: { S3Key: { Rules: [{ Name: 'prefix', Value: 'a/b/' }] } } },
      ]);
      expect(ids(diagnoseTemplate(t))).toContain('pf-s3-notification-overlapping-filters');
    });

    test('disjoint suffixes keep overlapping prefixes legal', () => {
      const t = notif([
        { Event: 's3:ObjectCreated:*', Queue: q, Filter: { S3Key: { Rules: [{ Name: 'prefix', Value: 'a/' }, { Name: 'suffix', Value: '.jpg' }] } } },
        { Event: 's3:ObjectCreated:*', Queue: q, Filter: { S3Key: { Rules: [{ Name: 'prefix', Value: 'a/b/' }, { Name: 'suffix', Value: '.png' }] } } },
      ]);
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });

    test('disjoint event families never overlap', () => {
      const t = notif([
        { Event: 's3:ObjectCreated:*', Queue: q },
        { Event: 's3:ObjectRemoved:*', Queue: q },
      ]);
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });

    test('an unfiltered entry overlaps a filtered one across config kinds', () => {
      const t = bucket({
        NotificationConfiguration: {
          QueueConfigurations: [{ Event: 's3:ObjectCreated:*', Queue: q }],
          TopicConfigurations: [{ Event: 's3:ObjectCreated:Put', Topic: 'arn:aws:sns:ap-northeast-1:123456789012:t', Filter: { S3Key: { Rules: [{ Name: 'prefix', Value: 'x/' }] } } }],
        },
      });
      expect(ids(diagnoseTemplate(t))).toContain('pf-s3-notification-overlapping-filters');
    });
  });

  describe('pf-s3-lifecycle-days-order', () => {
    test('IA transition below 30 days alone is NOT flagged — the absolute minimum is gone (bench s01)', () => {
      const t = bucket({
        LifecycleConfiguration: { Rules: [{ Status: 'Enabled', Transitions: [{ StorageClass: 'STANDARD_IA', TransitionInDays: 5 }] }] },
      });
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-s3-objectlock-requires-versioning', () => {
    test('skips when ObjectLockEnabled is true — the bucket is created lock-enabled', () => {
      const t = bucket({
        ObjectLockEnabled: true,
        ObjectLockConfiguration: { ObjectLockEnabled: 'Enabled', Rule: { DefaultRetention: { Mode: 'GOVERNANCE', Days: 1 } } },
      });
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });

    test('skips when ObjectLockEnabled is unresolvable', () => {
      const t = {
        Parameters: { L: { Type: 'String' } },
        Resources: {
          B: {
            Type: 'AWS::S3::Bucket',
            Properties: {
              ObjectLockEnabled: { Ref: 'L' },
              ObjectLockConfiguration: { ObjectLockEnabled: 'Enabled', Rule: { DefaultRetention: { Mode: 'GOVERNANCE', Days: 1 } } },
            },
          },
        },
      };
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-s3-accelerate-dotted-name', () => {
    test('skips when BucketName is generated (absent)', () => {
      const t = bucket({ AccelerateConfiguration: { AccelerationStatus: 'Enabled' } });
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-s3-bucket-policy-action-resource', () => {
    const pol = (statement: Record<string, unknown>) => ({
      Resources: {
        B: { Type: 'AWS::S3::Bucket', Properties: {} },
        P: { Type: 'AWS::S3::BucketPolicy', Properties: { Bucket: { Ref: 'B' }, PolicyDocument: { Version: '2012-10-17', Statement: [statement] } } },
      },
    });

    test('a mixed resource list with an object ARN is legal', () => {
      const t = pol({
        Effect: 'Allow',
        Principal: '*',
        Action: ['s3:GetObject', 's3:ListBucket'],
        Resource: ['arn:aws:s3:::my-bucket', 'arn:aws:s3:::my-bucket/*'],
      });
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });

    test('fires on an action list whose object action has only literal bucket ARNs', () => {
      const t = pol({
        Effect: 'Allow',
        Principal: '*',
        Action: ['s3:PutObjectAcl'],
        Resource: ['arn:aws:s3:::my-bucket'],
      });
      expect(ids(diagnoseTemplate(t))).toContain('pf-s3-bucket-policy-action-resource');
    });

    test('an unresolvable resource entry mutes the statement', () => {
      const t = pol({
        Effect: 'Allow',
        Principal: '*',
        Action: 's3:GetObject',
        Resource: [{ 'Fn::GetAtt': ['B', 'Arn'] }, { 'Fn::Sub': '${B.Arn}/*' }],
      });
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });

    test('bucket-level actions on bucket ARNs stay silent', () => {
      const t = pol({
        Effect: 'Allow',
        Principal: '*',
        Action: 's3:ListBucket',
        Resource: { 'Fn::GetAtt': ['B', 'Arn'] },
      });
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });
});

describe('cloudwatch logs rules', () => {
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);

  describe('pf-logs-subscription-kinesis-role', () => {
    const sf = (props: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
      Resources: {
        LG: { Type: 'AWS::Logs::LogGroup', Properties: {} },
        SF: { Type: 'AWS::Logs::SubscriptionFilter', Properties: { LogGroupName: { Ref: 'LG' }, FilterPattern: '', ...props } },
        ...extra,
      },
    });

    test('an in-template stream via GetAtt is a provable Kinesis destination', () => {
      const t = sf(
        { DestinationArn: { 'Fn::GetAtt': ['Stream', 'Arn'] } },
        { Stream: { Type: 'AWS::Kinesis::Stream', Properties: { ShardCount: 1 } } },
      );
      expect(ids(diagnoseTemplate(t, 'ap-northeast-1'))).toContain('pf-logs-subscription-kinesis-role');
    });

    test('a Lambda destination without RoleArn stays silent — only vendor kinesis was measured', () => {
      const t = sf({ DestinationArn: { 'Fn::Sub': 'arn:aws:lambda:${AWS::Region}:${AWS::AccountId}:function:f' } });
      expect(ids(diagnoseTemplate(t, 'ap-northeast-1'))).toHaveLength(0);
    });

    test('an unresolvable RoleArn counts as present', () => {
      const t = {
        Parameters: { R: { Type: 'String' } },
        Resources: {
          LG: { Type: 'AWS::Logs::LogGroup', Properties: {} },
          SF: {
            Type: 'AWS::Logs::SubscriptionFilter',
            Properties: {
              LogGroupName: { Ref: 'LG' },
              FilterPattern: '',
              DestinationArn: { 'Fn::Sub': 'arn:aws:kinesis:${AWS::Region}:${AWS::AccountId}:stream/s' },
              RoleArn: { Ref: 'R' },
            },
          },
        },
      };
      expect(ids(diagnoseTemplate(t, 'ap-northeast-1'))).toHaveLength(0);
    });
  });

  describe('pf-logs-filter-pattern-bracket', () => {
    test('surrounding whitespace does not hide the unbalanced bracket', () => {
      const t = {
        Resources: {
          LG: { Type: 'AWS::Logs::LogGroup', Properties: {} },
          MF: {
            Type: 'AWS::Logs::MetricFilter',
            Properties: {
              LogGroupName: { Ref: 'LG' },
              FilterPattern: '  [ip, status  ',
              MetricTransformations: [{ MetricName: 'm', MetricNamespace: 'cdkpf', MetricValue: '1' }],
            },
          },
        },
      };
      expect(ids(diagnoseTemplate(t))).toContain('pf-logs-filter-pattern-bracket');
    });
  });
});

describe('eventbridge rules', () => {
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);

  const rule = (props: Record<string, unknown>, parameters?: Record<string, unknown>) => ({
    ...(parameters ? { Parameters: parameters } : {}),
    Resources: {
      Q: { Type: 'AWS::SQS::Queue', Properties: {} },
      R: { Type: 'AWS::Events::Rule', Properties: props },
    },
  });
  const QARN = { 'Fn::GetAtt': ['Q', 'Arn'] };

  describe('pf-events-pattern-scalar-value', () => {
    test('a nested scalar is out of scope — only the top level was bench-verified', () => {
      const t = rule({ EventPattern: { detail: { state: 'x' } }, Targets: [{ Id: 't1', Arn: QARN }] });
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-events-pattern-empty', () => {
    test('an empty pattern next to a ScheduleExpression is not the verified shape', () => {
      const t = rule({ EventPattern: {}, ScheduleExpression: 'rate(5 minutes)', Targets: [{ Id: 't1', Arn: QARN }] });
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-events-input-transformer-placeholders', () => {
    test('predefined aws.events.* variables need no declaration even without InputPathsMap', () => {
      const t = rule({
        EventPattern: { source: ['aws.ec2'] },
        Targets: [{ Id: 't1', Arn: QARN, InputTransformer: { InputTemplate: '"rule <aws.events.rule-name>"' } }],
      });
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });

    test('an unresolvable InputPathsMap mutes the rule', () => {
      const t = rule(
        {
          EventPattern: { source: ['aws.ec2'] },
          Targets: [{ Id: 't1', Arn: QARN, InputTransformer: { InputPathsMap: { Ref: 'M' }, InputTemplate: '"<x>"' } }],
        },
        { M: { Type: 'String' } },
      );
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-scheduler-rate-positive', () => {
    test('extra spacing inside a valid rate() stays silent', () => {
      const t = {
        Resources: {
          S: {
            Type: 'AWS::Scheduler::Schedule',
            Properties: {
              FlexibleTimeWindow: { Mode: 'OFF' },
              ScheduleExpression: 'rate( 2 hours )',
              Target: { Arn: 'arn:aws:sqs:ap-northeast-1:123456789012:q', RoleArn: 'arn:aws:iam::123456789012:role/r' },
            },
          },
        },
      };
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });
});

describe('cloudwatch alarm rules', () => {
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);
  const alarm = (props: Record<string, unknown>, parameters?: Record<string, unknown>) => ({
    ...(parameters ? { Parameters: parameters } : {}),
    Resources: { A: { Type: 'AWS::CloudWatch::Alarm', Properties: { ComparisonOperator: 'GreaterThanThreshold', EvaluationPeriods: 1, ...props } } },
  });
  const ms = (n: string) => ({ Metric: { MetricName: n, Namespace: 'cdkpf' }, Period: 60, Stat: 'Average' });

  describe('pf-cloudwatch-metric-query-returndata', () => {
    test('an unresolvable ReturnData makes the count unknowable — rule skips', () => {
      const t = alarm(
        { Metrics: [{ Id: 'm1', MetricStat: ms('x') }, { Id: 'm2', MetricStat: ms('y'), ReturnData: { Ref: 'P' } }], Threshold: 1 },
        { P: { Type: 'String' } },
      );
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-cloudwatch-composite-alarm-rule-syntax', () => {
    test('AT_LEAST and parenthesized groups are valid starts', () => {
      const t = {
        Resources: {
          C: { Type: 'AWS::CloudWatch::CompositeAlarm', Properties: { AlarmRule: 'AT_LEAST(2, ALARM("a"), ALARM("b"), ALARM("c"))' } },
          D: { Type: 'AWS::CloudWatch::CompositeAlarm', Properties: { AlarmRule: '(ALARM("a") AND OK("b"))' } },
        },
      };
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-cloudwatch-alarm-threshold', () => {
    test('a range operator with ThresholdMetricId and no Threshold is the anomaly-detection happy path', () => {
      const t = alarm({
        ComparisonOperator: 'LessThanLowerOrGreaterThanUpperThreshold',
        ThresholdMetricId: 'ad1',
        Metrics: [
          { Id: 'ad1', Expression: 'ANOMALY_DETECTION_BAND(m1, 2)' },
          { Id: 'm1', MetricStat: ms('x'), ReturnData: false },
        ],
      });
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-cloudwatch-alarm-period', () => {
    test('high-resolution values and multiples of 60 stay silent', () => {
      const ok = (p: number) => alarm({ MetricName: 'x', Namespace: 'cdkpf', Statistic: 'Average', Period: p, Threshold: 1 });
      expect(ids(diagnoseTemplate(ok(10)))).toHaveLength(0);
      expect(ids(diagnoseTemplate(ok(300)))).toHaveLength(0);
      expect(ids(diagnoseTemplate(ok(90)))).toContain('pf-cloudwatch-alarm-period');
    });
  });
});

describe('api gateway rules', () => {
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);
  const rest = (extra: Record<string, unknown>) => ({
    Resources: { Api: { Type: 'AWS::ApiGateway::RestApi', Properties: { Name: 'p' } }, ...extra },
  });
  const v2 = (props: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
    Resources: { Api: { Type: 'AWS::ApiGatewayV2::Api', Properties: { Name: 'p', ProtocolType: 'HTTP', ...props } }, ...extra },
  });

  describe('pf-apigw-integration-http-method', () => {
    test('MOCK integrations do not need IntegrationHttpMethod', () => {
      const t = rest({
        M: {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            RestApiId: { Ref: 'Api' },
            ResourceId: { 'Fn::GetAtt': ['Api', 'RootResourceId'] },
            HttpMethod: 'GET',
            AuthorizationType: 'NONE',
            Integration: { Type: 'MOCK' },
          },
        },
      });
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-apigw-deployment-no-methods', () => {
    test('an OpenAPI Body can define methods invisibly — rule skips', () => {
      const t = {
        Resources: {
          Api: {
            Type: 'AWS::ApiGateway::RestApi',
            Properties: { Body: { openapi: '3.0.1', info: { title: 'p', version: '1' }, paths: {} } },
          },
          Dep: { Type: 'AWS::ApiGateway::Deployment', Properties: { RestApiId: { Ref: 'Api' } } },
        },
      };
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });

    test('an imported rest api id is outside the template — rule skips', () => {
      const t = {
        Resources: {
          Dep: { Type: 'AWS::ApiGateway::Deployment', Properties: { RestApiId: 'abc123' } },
        },
      };
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-apigw-stage-variable-value', () => {
    test('every documented symbol including space is legal', () => {
      const t = rest({
        M: {
          Type: 'AWS::ApiGateway::Method',
          Properties: {
            RestApiId: { Ref: 'Api' },
            ResourceId: { 'Fn::GetAtt': ['Api', 'RootResourceId'] },
            HttpMethod: 'GET',
            AuthorizationType: 'NONE',
            Integration: { Type: 'MOCK' },
          },
        },
        Dep: { Type: 'AWS::ApiGateway::Deployment', DependsOn: 'M', Properties: { RestApiId: { Ref: 'Api' } } },
        St: {
          Type: 'AWS::ApiGateway::Stage',
          Properties: {
            RestApiId: { Ref: 'Api' },
            DeploymentId: { Ref: 'Dep' },
            StageName: 'dev',
            Variables: { a: 'v1 v2-x.y_z:8/p?q=1&r=2,end' },
          },
        },
      });
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-apigw-model-schema-type', () => {
    test('a schema without type, or with an array type, is out of scope', () => {
      const model = (schema: unknown) =>
        rest({
          Mo: {
            Type: 'AWS::ApiGateway::Model',
            Properties: { RestApiId: { Ref: 'Api' }, ContentType: 'application/json', Schema: schema },
          },
        });
      expect(ids(diagnoseTemplate(model({ properties: { id: { type: 'string' } } })))).toHaveLength(0);
      expect(ids(diagnoseTemplate(model({ type: ['object', 'null'] })))).toHaveLength(0);
      expect(ids(diagnoseTemplate(model({ type: 'String' })))).toContain('pf-apigw-model-schema-type');
    });
  });

  describe('pf-apigwv2-http-route-selection', () => {
    test('both deploy-verified spellings stay silent', () => {
      expect(ids(diagnoseTemplate(v2({ RouteSelectionExpression: '$request.method $request.path' })))).toHaveLength(0);
      expect(ids(diagnoseTemplate(v2({ RouteSelectionExpression: '${request.method} ${request.path}' })))).toHaveLength(0);
    });
  });

  describe('pf-apigwv2-http-route-key', () => {
    test('websocket route keys are free-form — protocol guard mutes the rule', () => {
      const t = {
        Resources: {
          Api: {
            Type: 'AWS::ApiGatewayV2::Api',
            Properties: { Name: 'p', ProtocolType: 'WEBSOCKET', RouteSelectionExpression: '$request.body.action' },
          },
          Rt: { Type: 'AWS::ApiGatewayV2::Route', Properties: { ApiId: { Ref: 'Api' }, RouteKey: 'sendmessage' } },
        },
      };
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });

    test('a path with spaces is unmeasured — rule stays silent', () => {
      const t = v2({}, {
        Rt: { Type: 'AWS::ApiGatewayV2::Route', Properties: { ApiId: { Ref: 'Api' }, RouteKey: 'GET /a b' } },
      });
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });

    test('TRACE is deploy-verified as rejected', () => {
      const t = v2({}, {
        Rt: { Type: 'AWS::ApiGatewayV2::Route', Properties: { ApiId: { Ref: 'Api' }, RouteKey: 'TRACE /items' } },
      });
      expect(ids(diagnoseTemplate(t))).toContain('pf-apigwv2-http-route-key');
    });
  });

  describe('pf-apigwv2-request-authorizer-payload-version', () => {
    test('websocket REQUEST authorizers must not set the property — guard mutes the rule', () => {
      const t = {
        Resources: {
          Api: {
            Type: 'AWS::ApiGatewayV2::Api',
            Properties: { Name: 'p', ProtocolType: 'WEBSOCKET', RouteSelectionExpression: '$request.body.action' },
          },
          Auth: {
            Type: 'AWS::ApiGatewayV2::Authorizer',
            Properties: {
              ApiId: { Ref: 'Api' },
              Name: 'auth',
              AuthorizerType: 'REQUEST',
              AuthorizerUri: 'arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:f/invocations',
              IdentitySource: ['route.request.header.Authorization'],
            },
          },
        },
      };
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });
});

describe('cognito rules', () => {
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);
  const pool = (props: Record<string, unknown>) => ({
    Resources: { UP: { Type: 'AWS::Cognito::UserPool', Properties: { UserPoolName: 'p', ...props } } },
  });
  const client = (props: Record<string, unknown>, parameters?: Record<string, unknown>) => ({
    ...(parameters ? { Parameters: parameters } : {}),
    Resources: {
      UP: { Type: 'AWS::Cognito::UserPool', Properties: { UserPoolName: 'p' } },
      C: { Type: 'AWS::Cognito::UserPoolClient', Properties: { UserPoolId: { Ref: 'UP' }, ClientName: 'c', ...props } },
    },
  });

  describe('pf-cognito-token-validity-range', () => {
    test('the deploy-verified unit defaults apply when TokenValidityUnits is omitted', () => {
      expect(ids(diagnoseTemplate(client({ AccessTokenValidity: 25 })))).toContain('pf-cognito-token-validity-range');
      expect(ids(diagnoseTemplate(client({ RefreshTokenValidity: 4000 })))).toContain('pf-cognito-token-validity-range');
      expect(ids(diagnoseTemplate(client({ AccessTokenValidity: 12 })))).toHaveLength(0);
    });

    test('an unresolvable unit makes the duration unknowable — rule skips', () => {
      const t = client(
        { TokenValidityUnits: { AccessToken: { Ref: 'U' } }, AccessTokenValidity: 25 },
        { U: { Type: 'String' } },
      );
      expect(ids(diagnoseTemplate(t))).toHaveLength(0);
    });
  });

  describe('pf-cognito-token-expiration-order', () => {
    test('cross-unit comparison normalizes to seconds', () => {
      const ok = client({
        TokenValidityUnits: { AccessToken: 'hours', RefreshToken: 'days' },
        AccessTokenValidity: 23,
        RefreshTokenValidity: 1,
      });
      expect(ids(diagnoseTemplate(ok))).toHaveLength(0);
      const bad = client({
        TokenValidityUnits: { AccessToken: 'minutes', RefreshToken: 'minutes' },
        AccessTokenValidity: 200,
        RefreshTokenValidity: 90,
      });
      expect(ids(diagnoseTemplate(bad))).toContain('pf-cognito-token-expiration-order');
    });
  });

  describe('pf-cognito-mfa-sms-config', () => {
    test('declared factors mute the rule (TOTP-only pools deploy, bench c05b)', () => {
      expect(ids(diagnoseTemplate(pool({ MfaConfiguration: 'ON', EnabledMfas: ['SOFTWARE_TOKEN_MFA'] })))).toHaveLength(0);
      expect(ids(diagnoseTemplate(pool({ MfaConfiguration: 'OFF' })))).toHaveLength(0);
      expect(ids(diagnoseTemplate(pool({ MfaConfiguration: 'OPTIONAL' })))).toContain('pf-cognito-mfa-sms-config');
    });
  });

  describe('pf-cognito-client-credentials-secret', () => {
    test('GenerateSecret omitted defaults to false — rule fires; unresolvable skips', () => {
      const flows = {
        AllowedOAuthFlowsUserPoolClient: true,
        AllowedOAuthFlows: ['client_credentials'],
        AllowedOAuthScopes: ['rs/read'],
      };
      expect(ids(diagnoseTemplate(client(flows)))).toContain('pf-cognito-client-credentials-secret');
      const unresolvable = client({ ...flows, GenerateSecret: { Ref: 'G' } }, { G: { Type: 'String' } });
      expect(ids(diagnoseTemplate(unresolvable))).not.toContain('pf-cognito-client-credentials-secret');
    });
  });
});

describe('pf-cognito-domain-reserved-word', () => {
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);
  const domain = (d: string) => ({
    Resources: {
      UP: { Type: 'AWS::Cognito::UserPool', Properties: { UserPoolName: 'p' } },
      Dom: { Type: 'AWS::Cognito::UserPoolDomain', Properties: { UserPoolId: { Ref: 'UP' }, Domain: d } },
    },
  });

  test('reserved words match per hyphen segment, not substring (bench c07e: -awsome- deploys)', () => {
    expect(ids(diagnoseTemplate(domain('my-awsome-app')))).toHaveLength(0);
    expect(ids(diagnoseTemplate(domain('my-aws-app')))).toContain('pf-cognito-domain-reserved-word');
    expect(ids(diagnoseTemplate(domain('login-amazon')))).toContain('pf-cognito-domain-reserved-word');
  });
});

describe('lambda function and esm rules', () => {
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);
  const fn = (props: Record<string, unknown>) => ({
    Resources: {
      F: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          Role: 'arn:aws:iam::123456789012:role/r',
          Code: { ZipFile: 'def handler(e, c):\n    return 0\n' },
          Runtime: 'python3.12',
          Handler: 'index.handler',
          ...props,
        },
      },
    },
  });
  const esm = (props: Record<string, unknown>) => ({
    Resources: {
      M: {
        Type: 'AWS::Lambda::EventSourceMapping',
        Properties: { FunctionName: 'my-fn', ...props },
      },
    },
  });

  describe('dead letter config rules', () => {
    test('a region-less s3 arn violates both the region and service rules (bench dl01)', () => {
      const t = fn({ DeadLetterConfig: { TargetArn: 'arn:aws:s3:::my-bucket' } });
      const fired = ids(diagnoseTemplate(t, 'us-east-1'));
      expect(fired).toContain('pf-lambda-dlq-region');
      expect(fired).toContain('pf-lambda-dlq-service');
    });

    test('without a deploy region the region rule skips but the service rule still fires', () => {
      const t = fn({ DeadLetterConfig: { TargetArn: 'arn:aws:lambda:us-east-1:123456789012:function:x' } });
      const fired = ids(diagnoseTemplate(t));
      expect(fired).not.toContain('pf-lambda-dlq-region');
      expect(fired).toContain('pf-lambda-dlq-service');
    });
  });

  describe('event source mapping rules stay stream-agnostic', () => {
    const KINESIS = 'arn:aws:kinesis:us-east-1:123456789012:stream/s';
    test('kinesis sources take StartingPosition and big batches without a window', () => {
      const t1 = esm({ EventSourceArn: KINESIS, StartingPosition: 'LATEST' });
      const t2 = esm({ EventSourceArn: KINESIS, StartingPosition: 'LATEST', BatchSize: 100 });
      expect(ids(diagnoseTemplate(t1))).toHaveLength(0);
      expect(ids(diagnoseTemplate(t2))).toHaveLength(0);
    });

    test('a literal .fifo arn trips the fifo window rule', () => {
      const t = esm({
        EventSourceArn: 'arn:aws:sqs:us-east-1:123456789012:q.fifo',
        MaximumBatchingWindowInSeconds: 10,
      });
      expect(ids(diagnoseTemplate(t))).toContain('pf-lambda-esm-fifo-batching-window');
    });

    test('an explicit window of 0 still counts as no window', () => {
      const t = esm({
        EventSourceArn: 'arn:aws:sqs:us-east-1:123456789012:q',
        BatchSize: 100,
        MaximumBatchingWindowInSeconds: 0,
      });
      expect(ids(diagnoseTemplate(t))).toContain('pf-lambda-esm-batchsize-window');
    });
  });

  describe('code shape rules', () => {
    test('S3Key without S3Bucket is the other half of the pair', () => {
      const t = fn({});
      (t.Resources.F.Properties as Record<string, unknown>).Code = { S3Key: 'code.zip' };
      expect(ids(diagnoseTemplate(t))).toContain('pf-lambda-code-s3-pair');
    });

    test('ZipFile alongside ImageUri trips the exclusive rule', () => {
      const t = fn({});
      (t.Resources.F.Properties as Record<string, unknown>).Code = {
        ZipFile: 'def handler(e, c): pass',
        ImageUri: '123456789012.dkr.ecr.us-east-1.amazonaws.com/repo:tag',
      };
      expect(ids(diagnoseTemplate(t))).toContain('pf-lambda-code-zipfile-exclusive');
    });
  });
});

describe('firehose rules', () => {
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);
  const stream = (props: Record<string, unknown>) => ({
    Resources: { DS: { Type: 'AWS::KinesisFirehose::DeliveryStream', Properties: props } },
  });
  const dest = {
    BucketARN: 'arn:aws:s3:::my-bucket',
    RoleARN: 'arn:aws:iam::123456789012:role/firehose-role',
  };

  test('the plain S3 destination variant also counts as the one destination', () => {
    expect(ids(diagnoseTemplate(stream({ S3DestinationConfiguration: dest })))).toHaveLength(0);
  });

  test('dynamic partitioning rules stay silent when the feature is off', () => {
    const t = stream({
      ExtendedS3DestinationConfiguration: {
        ...dest,
        DynamicPartitioningConfiguration: { Enabled: false },
        BufferingHints: { SizeInMBs: 5, IntervalInSeconds: 300 },
        Prefix: 'data/plain/',
      },
    });
    expect(ids(diagnoseTemplate(t))).toHaveLength(0);
  });

  test('DirectPut with a source configuration deploys (bench f06) — no rule fires', () => {
    const t = stream({
      DeliveryStreamType: 'DirectPut',
      KinesisStreamSourceConfiguration: {
        KinesisStreamARN: 'arn:aws:kinesis:us-east-1:123456789012:stream/s',
        RoleARN: 'arn:aws:iam::123456789012:role/firehose-role',
      },
      ExtendedS3DestinationConfiguration: dest,
    });
    expect(ids(diagnoseTemplate(t))).toHaveLength(0);
  });
});
