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
    const found = blockers(ds);
    // このテストは二役: 新規ルールに対しては「エンジンと重複したので書くな」、
    // 既存ルールに対しては「エンジンが追いついたので退役させろ」の合図になる。
    // 後者は aws-cdk-lib を上げた時にだけ赤くなる（bench/out/redundancy.jsonl と同じ判定）。
    expect(found.map((d) => `${d.severity}/${d.source}/${d.ruleId}: ${d.message}`
      + ` >>> the bundled engine now blocks ${rule.id} by itself — retire it:`
      + ` rm -rf rules/${rule.service}/${rule.id}/ && npx projen bundle-rules`
      + ' (AGENTS.md "Rule lifecycle"; npx projen redundancy-scan lists them all)'))
      .toHaveLength(0);
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

describe('iam policy document rules', () => {
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);
  const TRUST = {
    Version: '2012-10-17',
    Statement: [{ Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' }],
  };
  const inline = (stmt: unknown) => ({
    Resources: {
      R: {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: TRUST,
          Policies: [{ PolicyName: 'p', PolicyDocument: { Version: '2012-10-17', Statement: stmt } }],
        },
      },
    },
  });

  test('intrinsic resources surface as marker objects and stay unjudged (measured)', () => {
    const t = {
      Resources: {
        B: { Type: 'AWS::S3::Bucket', Properties: {} },
        R: {
          Type: 'AWS::IAM::Role',
          Properties: {
            AssumeRolePolicyDocument: TRUST,
            Policies: [
              {
                PolicyName: 'p',
                PolicyDocument: {
                  Version: '2012-10-17',
                  Statement: [
                    { Effect: 'Allow', Action: 's3:GetObject', Resource: { 'Fn::GetAtt': ['B', 'Arn'] } },
                  ],
                },
              },
            ],
          },
        },
      },
    };
    expect(ids(diagnoseTemplate(t))).toHaveLength(0);
  });

  test('a single statement object (not array) is handled', () => {
    const t = inline({ Effect: 'Allow', Action: 'GetObject', Resource: '*' });
    expect(ids(diagnoseTemplate(t))).toContain('pf-iam-policy-action-format');
  });

  test('operator grammar accepts prefixes and IfExists, rejects the bare typo', () => {
    const cond = (c: unknown) => inline([{ Effect: 'Allow', Action: 's3:GetObject', Resource: '*', Condition: c }]);
    expect(ids(diagnoseTemplate(cond({ 'ForAllValues:StringEquals': { 'aws:TagKeys': ['a'] } })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(cond({ NumericLessThanEqualsIfExists: { 'aws:MultiFactorAuthAge': '300' } })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(cond({ StringEqual: { 'aws:username': 'x' } })))).toContain(
      'pf-iam-policy-condition-operator',
    );
  });

  test('wildcard action and NotResource-only statements are legal shapes', () => {
    expect(ids(diagnoseTemplate(inline([{ Effect: 'Allow', Action: '*', Resource: '*' }])))).toHaveLength(0);
    expect(
      ids(diagnoseTemplate(inline([{ Effect: 'Deny', Action: 's3:GetObject', NotResource: 'arn:aws:s3:::ok/*' }]))),
    ).toHaveLength(0);
  });
});

describe('ec2 and vpc rules', () => {
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);
  const R = 'us-east-1';
  const vpc = (cidr: string) => ({ Resources: { V: { Type: 'AWS::EC2::VPC', Properties: { CidrBlock: cidr } } } });
  const sgIn = (entry: Record<string, unknown>) => ({
    Resources: { G: { Type: 'AWS::EC2::SecurityGroup', Properties: { GroupDescription: 'x', VpcId: 'vpc-11112222', SecurityGroupIngress: [{ IpProtocol: 'tcp', FromPort: 80, ToPort: 80, ...entry }] } } },
  });
  const inst = (type: string, image: unknown) => ({
    Resources: { I: { Type: 'AWS::EC2::Instance', Properties: { InstanceType: type, ImageId: image } } },
  });
  const ARM_PATH = '{{resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-arm64}}';
  const X86_PATH = '{{resolve:ssm:/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64}}';

  test('vpc cidr netmask: /16 and /28 legal, /8 and /29 flagged (bench e01/e01b)', () => {
    expect(ids(diagnoseTemplate(vpc('10.0.0.0/16')))).toHaveLength(0);
    expect(ids(diagnoseTemplate(vpc('10.255.0.0/28')))).toHaveLength(0);
    expect(ids(diagnoseTemplate(vpc('10.0.0.0/8')))).toContain('pf-ec2-vpc-cidr-block-size');
    expect(ids(diagnoseTemplate(vpc('10.0.0.0/29')))).toContain('pf-ec2-vpc-cidr-block-size');
  });

  test('sg rule sources: embedded zero-source is legal (bench e03) but standalone needs exactly one (e03c/e03e)', () => {
    expect(ids(diagnoseTemplate(sgIn({})))).toHaveLength(0);
    expect(ids(diagnoseTemplate(sgIn({ CidrIp: '10.1.0.0/24', CidrIpv6: '::/0' })))).toContain('pf-ec2-sg-source-exclusive');
    const standalone = (props: Record<string, unknown>) => ({
      Resources: { X: { Type: 'AWS::EC2::SecurityGroupIngress', Properties: { GroupId: 'sg-11112222', IpProtocol: 'tcp', FromPort: 80, ToPort: 80, ...props } } },
    });
    expect(ids(diagnoseTemplate(standalone({})))).toContain('pf-ec2-sg-source-exclusive');
    expect(ids(diagnoseTemplate(standalone({ CidrIp: '10.1.0.0/24' })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(standalone({ CidrIp: '10.1.0.0/24', SourcePrefixListId: 'pl-11112222' })))).toContain('pf-ec2-sg-source-exclusive');
  });

  test('malformed CidrIp octet/prefix flagged; /32 boundary and intrinsic values silent (bench e14/e14b)', () => {
    expect(ids(diagnoseTemplate(sgIn({ CidrIp: '10.0.0.0/32' })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(sgIn({ CidrIp: '10.0.999.0/24' })))).toContain('pf-ec2-sg-cidr-valid');
    expect(ids(diagnoseTemplate(sgIn({ CidrIp: '10.0.0.0/33' })))).toContain('pf-ec2-sg-cidr-valid');
    expect(ids(diagnoseTemplate(sgIn({ CidrIp: { 'Fn::ImportValue': 'net-cidr' } })))).toHaveLength(0);
  });

  test('route target count: a Ref-wired target is the one target; zero and two fire (bench e08/e08b)', () => {
    const route = (extra: Record<string, unknown>) => ({
      Resources: {
        G: { Type: 'AWS::EC2::InternetGateway' },
        X: { Type: 'AWS::EC2::Route', Properties: { RouteTableId: 'rtb-11112222', DestinationCidrBlock: '0.0.0.0/0', ...extra } },
      },
    });
    expect(ids(diagnoseTemplate(route({ GatewayId: { Ref: 'G' } })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(route({})))).toContain('pf-ec2-route-target-exactly-one');
    expect(ids(diagnoseTemplate(route({ GatewayId: { Ref: 'G' }, NatGatewayId: 'nat-0aaaabbbbccccdddd1' })))).toContain('pf-ec2-route-target-exactly-one');
  });

  test('nat gateway: explicit public without AllocationId fires; private without AllocationId is legal (bench e07/e07b)', () => {
    const nat = (props: Record<string, unknown>) => ({
      Resources: { N: { Type: 'AWS::EC2::NatGateway', Properties: { SubnetId: 'subnet-11112222', ...props } } },
    });
    expect(ids(diagnoseTemplate(nat({ ConnectivityType: 'public' })))).toContain('pf-ec2-natgw-allocation');
    expect(ids(diagnoseTemplate(nat({ ConnectivityType: 'private' })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(nat({ ConnectivityType: 'private', AllocationId: 'eipalloc-11112222' })))).toContain('pf-ec2-natgw-allocation');
  });

  test('vpce service region: fires for both endpoint types, mutes on ServiceRegion, skips non-region segments (bench e09/e09c)', () => {
    const vpce = (props: Record<string, unknown>) => ({
      Resources: { P: { Type: 'AWS::EC2::VPCEndpoint', Properties: { VpcId: 'vpc-11112222', ...props } } },
    });
    expect(ids(diagnoseTemplate(vpce({ ServiceName: 'com.amazonaws.ap-northeast-1.s3' }), R))).toContain('pf-ec2-vpce-service-region');
    expect(ids(diagnoseTemplate(vpce({ ServiceName: 'com.amazonaws.ap-northeast-1.sqs', VpcEndpointType: 'Interface' }), R))).toContain('pf-ec2-vpce-service-region');
    expect(ids(diagnoseTemplate(vpce({ ServiceName: 'com.amazonaws.ap-northeast-1.sqs', VpcEndpointType: 'Interface', ServiceRegion: 'ap-northeast-1' }), R))).toHaveLength(0);
    expect(ids(diagnoseTemplate(vpce({ ServiceName: 'com.amazonaws.s3-global.accesspoint', VpcEndpointType: 'Interface' }), R))).toHaveLength(0);
    // gateway-service judgment is region-independent: fires even without deploy_region
    expect(ids(diagnoseTemplate(vpce({ ServiceName: 'com.amazonaws.ap-northeast-1.sqs' })))).toContain('pf-ec2-vpce-gateway-service');
    expect(ids(diagnoseTemplate(vpce({ ServiceName: 'com.amazonaws.ap-northeast-1.sqs' })))).not.toContain('pf-ec2-vpce-service-region');
  });

  test('instance arch heuristic: g4dn is x86, c7gn and a1 are arm, mac and literal AMIs are skipped (bench e12)', () => {
    expect(ids(diagnoseTemplate(inst('g4dn.xlarge', ARM_PATH)))).toContain('pf-ec2-instance-ami-arch');
    expect(ids(diagnoseTemplate(inst('c7gn.large', X86_PATH)))).toContain('pf-ec2-instance-ami-arch');
    expect(ids(diagnoseTemplate(inst('a1.large', X86_PATH)))).toContain('pf-ec2-instance-ami-arch');
    expect(ids(diagnoseTemplate(inst('t4g.micro', ARM_PATH)))).toHaveLength(0);
    expect(ids(diagnoseTemplate(inst('mac2.metal', ARM_PATH)))).toHaveLength(0);
    expect(ids(diagnoseTemplate(inst('t3.micro', 'ami-11112222333344445')))).toHaveLength(0);
  });

  test('placement group: spread strategy and literal (pre-existing) group names stay silent (bench e11 family)', () => {
    const pgTpl = (strategy: string | undefined, pg: unknown, type = 't3.micro') => ({
      Resources: {
        ...(strategy ? { P: { Type: 'AWS::EC2::PlacementGroup', Properties: { Strategy: strategy } } } : {}),
        I: { Type: 'AWS::EC2::Instance', Properties: { InstanceType: type, ImageId: X86_PATH, PlacementGroupName: pg } },
      },
    });
    expect(ids(diagnoseTemplate(pgTpl('cluster', { Ref: 'P' })))).toContain('pf-ec2-pg-cluster-burstable');
    expect(ids(diagnoseTemplate(pgTpl('spread', { Ref: 'P' })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(pgTpl(undefined, 'my-existing-group')))).toHaveLength(0);
    expect(ids(diagnoseTemplate(pgTpl('cluster', { Ref: 'P' }, 'c5.large')))).toHaveLength(0);
  });

  test('volume kms: explicit false fires like absence; unresolvable Encrypted stays silent (bench e06/e06b)', () => {
    const volT = (props: Record<string, unknown>) => ({
      Parameters: { Enc: { Type: 'String' } },
      Resources: { W: { Type: 'AWS::EC2::Volume', Properties: { AvailabilityZone: 'us-east-1a', VolumeType: 'gp3', Size: 10, KmsKeyId: 'alias/aws/ebs', ...props } } },
    });
    expect(ids(diagnoseTemplate(volT({ Encrypted: false })))).toContain('pf-ec2-volume-kms-encrypted');
    expect(ids(diagnoseTemplate(volT({ Encrypted: { Ref: 'Enc' } })))).toHaveLength(0);
  });
});

describe('rds and aurora rules', () => {
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);
  const baseInst = {
    Engine: 'postgres',
    DBInstanceClass: 'db.t4g.micro',
    AllocatedStorage: '20',
    MasterUsername: 'benchuser',
    MasterUserPassword: 'benchpass123',
  };
  const inst = (p: Record<string, unknown>) => ({
    Resources: { I: { Type: 'AWS::RDS::DBInstance', DeletionPolicy: 'Delete', UpdateReplacePolicy: 'Delete', Properties: { ...baseInst, ...p } } },
  });

  test('backup window duration handles zero-padded times and midnight wrap (to_number leading-zero pitfall)', () => {
    expect(ids(diagnoseTemplate(inst({ PreferredBackupWindow: '03:00-03:29', BackupRetentionPeriod: 7 })))).toContain('pf-rds-backup-window-duration');
    expect(ids(diagnoseTemplate(inst({ PreferredBackupWindow: '03:00-03:30', BackupRetentionPeriod: 7 })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(inst({ PreferredBackupWindow: '23:50-00:20', BackupRetentionPeriod: 7 })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(inst({ PreferredBackupWindow: '23:50-00:10', BackupRetentionPeriod: 7 })))).toContain('pf-rds-backup-window-duration');
  });

  test('window overlap: same-day intersection fires, adjacent windows and other maintenance days stay silent', () => {
    const w = (b: string, m: string) => inst({ PreferredBackupWindow: b, PreferredMaintenanceWindow: m, BackupRetentionPeriod: 7 });
    expect(ids(diagnoseTemplate(w('03:00-04:00', 'mon:03:30-mon:04:30')))).toContain('pf-rds-window-overlap');
    expect(ids(diagnoseTemplate(w('03:00-04:00', 'mon:04:00-mon:05:00')))).toHaveLength(0);
    expect(ids(diagnoseTemplate(w('03:00-04:00', 'Mon:03:30-Mon:04:30')))).toContain('pf-rds-window-overlap');
  });

  test('password rules ignore Secrets Manager dynamic references and non-literal values', () => {
    const secret = '{{resolve:secretsmanager:arn:aws:secretsmanager:us-east-1:123456789012:secret:x:SecretString:password}}';
    expect(ids(diagnoseTemplate(inst({ MasterUserPassword: secret })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(inst({ MasterUserPassword: 'has space x' })))).toContain('pf-rds-password-valid');
    expect(ids(diagnoseTemplate(inst({ MasterUserPassword: 'short' })))).toContain('pf-rds-password-valid');
  });

  test('gp3 threshold needs a custom setting; 400 GiB boundary and other engines stay silent', () => {
    expect(ids(diagnoseTemplate(inst({ StorageType: 'gp3', AllocatedStorage: '100' })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(inst({ StorageType: 'gp3', AllocatedStorage: '100', StorageThroughput: 500 })))).toContain('pf-rds-gp3-iops-storage-threshold');
    expect(ids(diagnoseTemplate(inst({ Engine: 'sqlserver-ex', AllocatedStorage: '100', StorageType: 'gp3', Iops: 12000, MasterUsername: 'benchuser', MasterUserPassword: 'benchpass123' })))).toHaveLength(0);
  });

  test('io1 ratio is scoped to the benched postgres/io1 pair; ratio 50 exactly is legal', () => {
    expect(ids(diagnoseTemplate(inst({ StorageType: 'io1', AllocatedStorage: '100', Iops: 5000 })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(inst({ StorageType: 'io1', AllocatedStorage: '100', Iops: 5001 })))).toContain('pf-rds-io1-iops-ratio');
    expect(ids(diagnoseTemplate(inst({ Engine: 'mysql', StorageType: 'io1', AllocatedStorage: '100', Iops: 6000 })))).toHaveLength(0);
  });

  test('backtrack: zero disables cleanly on any engine; range check only on aurora-mysql', () => {
    const cl = (p: Record<string, unknown>) => ({
      Resources: { C: { Type: 'AWS::RDS::DBCluster', DeletionPolicy: 'Delete', UpdateReplacePolicy: 'Delete', Properties: { Engine: 'aurora-postgresql', MasterUsername: 'benchuser', MasterUserPassword: 'benchpass123', ...p } } },
    });
    expect(ids(diagnoseTemplate(cl({ BacktrackWindow: 0 })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(cl({ BacktrackWindow: 3600 })))).toContain('pf-rds-backtrack');
    expect(ids(diagnoseTemplate(cl({ Engine: 'aurora-mysql', BacktrackWindow: 259200 })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(cl({ Engine: 'aurora-mysql', BacktrackWindow: 259201 })))).toContain('pf-rds-backtrack');
  });

  test('dbname: only the letter-start half is claimed - underscores deploy clean (bench r15b)', () => {
    expect(ids(diagnoseTemplate(inst({ DBName: 'bench_db' })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(inst({ DBName: '1abc' })))).toContain('pf-rds-dbname-format');
    expect(ids(diagnoseTemplate(inst({ Engine: 'mysql', DBName: '1abc' })))).toHaveLength(0);
  });
});

describe('batch rules', () => {
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);
  const IMG = 'public.ecr.aws/amazonlinux/amazonlinux:latest';
  const fargateJd = (vcpu: unknown, mem: unknown) => ({
    Resources: {
      J: {
        Type: 'AWS::Batch::JobDefinition',
        Properties: {
          Type: 'container',
          PlatformCapabilities: ['FARGATE'],
          ContainerProperties: {
            Image: IMG,
            ExecutionRoleArn: 'arn:aws:iam::123456789012:role/exec',
            ResourceRequirements: [{ Type: 'VCPU', Value: vcpu }, { Type: 'MEMORY', Value: mem }],
          },
        },
      },
    },
  });
  const ceT = (cr: Record<string, unknown>, p: Record<string, unknown> = {}) => ({
    Resources: {
      C: {
        Type: 'AWS::Batch::ComputeEnvironment',
        Properties: {
          Type: 'MANAGED',
          ComputeResources: { Type: 'FARGATE', MaxvCpus: 4, Subnets: ['subnet-11112222'], SecurityGroupIds: ['sg-11112222'], ...cr },
          ...p,
        },
      },
    },
  });

  test('fargate combo: "1.0" normalizes onto tier 1; the 0.25 tier is a set (1536 is not min+step math)', () => {
    expect(ids(diagnoseTemplate(fargateJd('1.0', '2048')))).toHaveLength(0);
    expect(ids(diagnoseTemplate(fargateJd('1.0', '1024')))).toContain('pf-batch-fargate-cpu-memory');
    expect(ids(diagnoseTemplate(fargateJd('0.25', '1536')))).toContain('pf-batch-fargate-cpu-memory');
    expect(ids(diagnoseTemplate(fargateJd('8', '20480')))).toHaveLength(0);
    expect(ids(diagnoseTemplate(fargateJd('8', '17000')))).toContain('pf-batch-fargate-cpu-memory');
  });

  test('fargate combo and exec-role rules stay silent for EC2-platform job definitions', () => {
    const t = fargateJd('0.25', '8192');
    (t.Resources.J.Properties as any).PlatformCapabilities = ['EC2'];
    delete (t.Resources.J.Properties.ContainerProperties as any).ExecutionRoleArn;
    expect(ids(diagnoseTemplate(t))).toHaveLength(0);
  });

  test('fargate-only CE fields: EC2 compute environments may use AllocationStrategy', () => {
    expect(ids(diagnoseTemplate(ceT({ Type: 'EC2', AllocationStrategy: 'BEST_FIT', InstanceTypes: ['optimal'], InstanceRole: 'r' })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(ceT({ Type: 'FARGATE_SPOT', InstanceTypes: ['optimal'] })))).toContain('pf-batch-fargate-ce-fields');
  });

  test('unmanaged rule is scoped to Fargate resource types; UNMANAGED + EC2 resources stay silent', () => {
    expect(ids(diagnoseTemplate(ceT({ Type: 'EC2', InstanceTypes: ['optimal'], InstanceRole: 'r' }, { Type: 'UNMANAGED' })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(ceT({ Type: 'FARGATE_SPOT' }, { Type: 'UNMANAGED' })))).toContain('pf-batch-unmanaged-fargate');
  });

  test('queue order: absent list is schema territory and stays silent here; empty list fires', () => {
    const q = (props: Record<string, unknown>) => ({ Resources: { Q: { Type: 'AWS::Batch::JobQueue', Properties: { Priority: 1, ...props } } } });
    expect(ids(diagnoseTemplate(q({ ComputeEnvironmentOrder: [] })))).toContain('pf-batch-queue-order-required');
    expect(ids(diagnoseTemplate(q({ ComputeEnvironmentOrder: [{ Order: 1, ComputeEnvironment: 'arn:aws:batch:us-east-1:123456789012:compute-environment/x' }] })))).toHaveLength(0);
  });

  test('retry attempts: only the benched upper edge fires; 0 stays silent (unbenched)', () => {
    const jdT = (attempts: number) => ({
      Resources: { J: { Type: 'AWS::Batch::JobDefinition', Properties: { Type: 'container', RetryStrategy: { Attempts: attempts }, ContainerProperties: { Image: IMG, ResourceRequirements: [{ Type: 'VCPU', Value: '1' }, { Type: 'MEMORY', Value: '2048' }] } } } },
    });
    expect(ids(diagnoseTemplate(jdT(11)))).toContain('pf-batch-retry-attempts');
    expect(ids(diagnoseTemplate(jdT(10)))).toHaveLength(0);
    expect(ids(diagnoseTemplate(jdT(0)))).toHaveLength(0);
  });
});

describe('elbv2 rules', () => {
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);
  const VPC = 'vpc-11112222';
  const tgT = (p: Record<string, unknown>) => ({
    Resources: { T: { Type: 'AWS::ElasticLoadBalancingV2::TargetGroup', Properties: { Protocol: 'HTTP', Port: 80, VpcId: VPC, TargetType: 'instance', ...p } } },
  });

  test('stickiness pairs are scoped to the benched combinations', () => {
    const attrs = (type: string) => [{ Key: 'stickiness.enabled', Value: 'true' }, { Key: 'stickiness.type', Value: type }];
    expect(ids(diagnoseTemplate(tgT({ Protocol: 'TCP', TargetGroupAttributes: attrs('lb_cookie') })))).toContain('pf-elbv2-stickiness-type-protocol');
    expect(ids(diagnoseTemplate(tgT({ TargetGroupAttributes: attrs('source_ip') })))).toContain('pf-elbv2-stickiness-type-protocol');
    expect(ids(diagnoseTemplate(tgT({ TargetGroupAttributes: attrs('lb_cookie') })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(tgT({ Protocol: 'UDP', TargetGroupAttributes: attrs('lb_cookie') })))).toHaveLength(0);
  });

  test('tcp health check path: explicit HTTP health check protocol overrides a TCP target group', () => {
    expect(ids(diagnoseTemplate(tgT({ Protocol: 'TCP', HealthCheckProtocol: 'HTTP', HealthCheckPath: '/h' })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(tgT({ Protocol: 'TCP', HealthCheckPath: '/h' })))).toContain('pf-elbv2-tcp-health-check-path');
    expect(ids(diagnoseTemplate(tgT({ HealthCheckPath: '/h' })))).toHaveLength(0);
  });

  test('listener protocol rule: NLB QUIC is legal per the service allow-set; literal LB ARNs stay silent', () => {
    const nlb = (proto: string, lbRef: unknown = { Ref: 'L' }) => ({
      Resources: {
        L: { Type: 'AWS::ElasticLoadBalancingV2::LoadBalancer', Properties: { Type: 'network', Scheme: 'internal', Subnets: ['subnet-11112222', 'subnet-33334444'] } },
        T: { Type: 'AWS::ElasticLoadBalancingV2::TargetGroup', Properties: { Protocol: 'TCP', Port: 80, VpcId: VPC, TargetType: 'instance' } },
        S: { Type: 'AWS::ElasticLoadBalancingV2::Listener', Properties: { LoadBalancerArn: lbRef, Protocol: proto, Port: 80, DefaultActions: [{ Type: 'forward', TargetGroupArn: { Ref: 'T' } }] } },
      },
    });
    expect(ids(diagnoseTemplate(nlb('QUIC')))).toHaveLength(0);
    expect(ids(diagnoseTemplate(nlb('HTTP')))).toContain('pf-elbv2-listener-protocol-lb-type');
    expect(ids(diagnoseTemplate(nlb('HTTP', 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/net/x/1')))).toHaveLength(0);
  });

  test('alb subnet count ignores NLBs and SubnetMappings-based load balancers', () => {
    const lb = (p: Record<string, unknown>) => ({ Resources: { L: { Type: 'AWS::ElasticLoadBalancingV2::LoadBalancer', Properties: { Scheme: 'internal', ...p } } } });
    expect(ids(diagnoseTemplate(lb({ Subnets: ['subnet-11112222'] })))).toContain('pf-elbv2-alb-subnet-count');
    expect(ids(diagnoseTemplate(lb({ Type: 'network', Subnets: ['subnet-11112222'] })))).toHaveLength(0);
    expect(ids(diagnoseTemplate(lb({ SubnetMappings: [{ SubnetId: 'subnet-11112222' }] })))).toHaveLength(0);
  });

  test('rule priorities only clash on the same listener', () => {
    const two = (arn2: unknown) => ({
      Resources: {
        R1: { Type: 'AWS::ElasticLoadBalancingV2::ListenerRule', Properties: { ListenerArn: 'arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/x/1/a', Priority: 10, Conditions: [], Actions: [] } },
        R2: { Type: 'AWS::ElasticLoadBalancingV2::ListenerRule', Properties: { ListenerArn: arn2, Priority: 10, Conditions: [], Actions: [] } },
      },
    });
    expect(ids(diagnoseTemplate(two('arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/x/1/a')))).toContain('pf-elbv2-rule-priority-unique');
    expect(ids(diagnoseTemplate(two('arn:aws:elasticloadbalancing:us-east-1:123456789012:listener/app/x/1/b')))).toHaveLength(0);
  });
});

describe('ecs service and cloudwatch dashboard rules', () => {
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);
  const IMG = 'public.ecr.aws/amazonlinux/amazonlinux:2023';
  const svcT = (svcProps: Record<string, unknown>, tdProps?: Record<string, unknown>) => ({
    Resources: {
      Cluster: { Type: 'AWS::ECS::Cluster', Properties: {} },
      TaskDef: { Type: 'AWS::ECS::TaskDefinition', Properties: tdProps ?? { NetworkMode: 'bridge', ContainerDefinitions: [{ Name: 'app', Image: IMG, Essential: true, Memory: 512 }] } },
      Service: { Type: 'AWS::ECS::Service', Properties: { Cluster: { Ref: 'Cluster' }, TaskDefinition: { Ref: 'TaskDef' }, ...svcProps } },
    },
  });
  const dashT = (body: unknown, name?: string) => ({
    Resources: { Dash: { Type: 'AWS::CloudWatch::Dashboard', Properties: { DashboardBody: typeof body === 'string' ? body : JSON.stringify(body), ...(name ? { DashboardName: name } : {}) } } },
  });
  const widget = { type: 'text', x: 0, y: 0, width: 6, height: 6, properties: { markdown: 'hi' } };

  test('daemon rejects DesiredCount even at 0 (bench sv03b)', () => {
    expect(ids(diagnoseTemplate(svcT({ LaunchType: 'EC2', SchedulingStrategy: 'DAEMON', DesiredCount: 0 })))).toContain('pf-ecs-service-daemon-desired-count');
    expect(ids(diagnoseTemplate(svcT({ LaunchType: 'EC2', SchedulingStrategy: 'DAEMON' })))).toHaveLength(0);
  });

  test('network configuration vs task definition mode is cross-resource; external task definitions stay silent', () => {
    const netcfg = { AwsvpcConfiguration: { Subnets: ['subnet-11112222'] } };
    expect(ids(diagnoseTemplate(svcT({ LaunchType: 'EC2', DesiredCount: 0, NetworkConfiguration: netcfg })))).toContain('pf-ecs-service-network-config-mode');
    const ext = {
      Resources: {
        Service: { Type: 'AWS::ECS::Service', Properties: { TaskDefinition: 'arn:aws:ecs:us-east-1:123456789012:task-definition/td:1', LaunchType: 'EC2', DesiredCount: 0, NetworkConfiguration: netcfg } },
      },
    };
    expect(ids(diagnoseTemplate(ext))).toHaveLength(0);
  });

  test('deployment percent bounds fire on both sides', () => {
    expect(ids(diagnoseTemplate(svcT({ LaunchType: 'EC2', DesiredCount: 0, DeploymentConfiguration: { MinimumHealthyPercent: 101 } })))).toContain('pf-ecs-service-deployment-percent');
    expect(ids(diagnoseTemplate(svcT({ LaunchType: 'EC2', DesiredCount: 0, DeploymentConfiguration: { MaximumPercent: 90 } })))).toContain('pf-ecs-service-deployment-percent');
    expect(ids(diagnoseTemplate(svcT({ LaunchType: 'EC2', DesiredCount: 0, DeploymentConfiguration: { MinimumHealthyPercent: 100, MaximumPercent: 100 } })))).toHaveLength(0);
  });

  test('fargate placement fires for strategies too (bench sv09b)', () => {
    const strategies = [{ Type: 'spread', Field: 'attribute:ecs.availability-zone' }];
    const netcfg = { AwsvpcConfiguration: { Subnets: ['subnet-11112222'] } };
    const fargateTd = { RequiresCompatibilities: ['FARGATE'], NetworkMode: 'awsvpc', Cpu: '256', Memory: '512', ContainerDefinitions: [{ Name: 'app', Image: IMG, Essential: true }] };
    expect(ids(diagnoseTemplate(svcT({ LaunchType: 'FARGATE', DesiredCount: 0, NetworkConfiguration: netcfg, PlacementStrategies: strategies }, fargateTd)))).toContain('pf-ecs-service-fargate-placement');
    expect(ids(diagnoseTemplate(svcT({ LaunchType: 'EC2', DesiredCount: 0, PlacementStrategies: strategies })))).toHaveLength(0);
  });

  test('MetricStat.Period is covered by the alarm period rule (bench w11)', () => {
    const alarm = (period: number) => ({
      Resources: {
        Alarm: { Type: 'AWS::CloudWatch::Alarm', Properties: { ComparisonOperator: 'GreaterThanThreshold', EvaluationPeriods: 1, Threshold: 1, Metrics: [{ Id: 'm1', ReturnData: true, MetricStat: { Metric: { MetricName: 'CPUUtilization', Namespace: 'AWS/EC2' }, Period: period, Stat: 'Average' } }] } },
      },
    });
    expect(ids(diagnoseTemplate(alarm(45)))).toContain('pf-cloudwatch-alarm-period');
    expect(ids(diagnoseTemplate(alarm(300)))).toHaveLength(0);
  });

  test('dashboard widget checks stay inside the parsed body', () => {
    expect(ids(diagnoseTemplate(dashT({ widgets: [{ type: 'metric', x: 0, y: 0, width: 6, height: 6 }] })))).toContain('pf-cloudwatch-dashboard-widget-fields');
    expect(ids(diagnoseTemplate(dashT({ widgets: [{ ...widget, x: 24 }] })))).toContain('pf-cloudwatch-dashboard-widget-position');
    expect(ids(diagnoseTemplate(dashT({ widgets: [{ ...widget, type: 'metricc' }] })))).toHaveLength(0);
    const intrinsicBody = {
      Resources: { Dash: { Type: 'AWS::CloudWatch::Dashboard', Properties: { DashboardBody: { 'Fn::Sub': '{"widgets":${W}' } } } },
    };
    expect(ids(diagnoseTemplate(intrinsicBody))).toHaveLength(0);
  });

  test('threshold metric id needs a ReturnData true match', () => {
    const alarm = (adReturnData: boolean) => ({
      Resources: {
        Alarm: { Type: 'AWS::CloudWatch::Alarm', Properties: { ComparisonOperator: 'LessThanLowerOrGreaterThanUpperThreshold', EvaluationPeriods: 1, ThresholdMetricId: 'ad1', Metrics: [{ Id: 'm1', ReturnData: !adReturnData, MetricStat: { Metric: { MetricName: 'CPUUtilization', Namespace: 'AWS/EC2' }, Period: 300, Stat: 'Average' } }, { Id: 'ad1', ReturnData: adReturnData, Expression: 'ANOMALY_DETECTION_BAND(m1, 2)' }] } },
      },
    });
    expect(ids(diagnoseTemplate(alarm(false)))).toContain('pf-cloudwatch-threshold-metric-id');
    expect(ids(diagnoseTemplate(alarm(true)))).toHaveLength(0);
  });
});

/**
 * SQS / SNS ルールのうち、fail フィクスチャ 1 枚では踏めない分岐:
 * JSON 文字列形のポリシー、Topic 内インライン Subscription、リテラル ARN、
 * リージョン束縛、Ref / Fn::GetAtt の区別。
 */
describe('sqs / sns rules', () => {
  const ids = (ds: Diagnostic[]) => ds.filter((d) => d.source === 'CUSTOM').map((d) => d.ruleId);
  const queue = (props: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({ Resources: { Q: { Type: 'AWS::SQS::Queue', Properties: props }, ...extra } });
  const topic = (props: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({ Resources: { T: { Type: 'AWS::SNS::Topic', Properties: props }, ...extra } });
  const sub = (props: Record<string, unknown>, topicProps: Record<string, unknown> = {}, extra: Record<string, unknown> = {}) => ({
    Resources: { T: { Type: 'AWS::SNS::Topic', Properties: topicProps }, S: { Type: 'AWS::SNS::Subscription', Properties: { TopicArn: { Ref: 'T' }, ...props } }, ...extra },
  });
  const Q = { Q: { Type: 'AWS::SQS::Queue', Properties: {} } };
  const QARN = { 'Fn::GetAtt': ['Q', 'Arn'] };

  test('sqs policies are read both as objects and as JSON strings', () => {
    expect(ids(diagnoseTemplate(queue({ RedrivePolicy: JSON.stringify({ deadLetterTargetArn: 'arn:aws:sqs:us-east-1:123456789012:dlq', maxReceiveCount: 1001 }) }))))
      .toContain('pf-sqs-redrive-policy');
    expect(ids(diagnoseTemplate(queue({ RedriveAllowPolicy: JSON.stringify({ redrivePermission: 'allowAll', sourceQueueArns: ['arn:aws:sqs:us-east-1:123456789012:s'] }) }))))
      .toContain('pf-sqs-redrive-allow-policy');
    expect(ids(diagnoseTemplate(queue({ RedrivePolicy: { deadLetterTargetArn: 'arn:aws:sns:us-east-1:123456789012:t', maxReceiveCount: '5' } }))))
      .toContain('pf-sqs-redrive-policy');
  });

  test('sqs FIFO-only attributes: enum branch and the DeduplicationScope=queue pairing', () => {
    expect(ids(diagnoseTemplate(queue({ FifoQueue: true, DeduplicationScope: 'foo' })))).toContain('pf-sqs-fifo-only-attributes');
    expect(ids(diagnoseTemplate(queue({ FifoQueue: true, FifoThroughputLimit: 'perMessageGroupId', DeduplicationScope: 'queue' })))).toContain('pf-sqs-high-throughput-pairing');
    expect(ids(diagnoseTemplate(queue({ FifoQueue: true, FifoThroughputLimit: 'perQueue', DeduplicationScope: 'queue' })))).toHaveLength(0);
  });

  test('sqs DLQ type via literal ARN, and region binding for DLQ / redrive-allow sources', () => {
    expect(ids(diagnoseTemplate(queue({ FifoQueue: true, RedrivePolicy: { deadLetterTargetArn: 'arn:aws:sqs:us-east-1:123456789012:dlq', maxReceiveCount: 5 } }))))
      .toContain('pf-sqs-dlq-same-type');
    expect(ids(diagnoseTemplate(queue({ RedrivePolicy: { deadLetterTargetArn: 'arn:aws:sqs:us-east-1:123456789012:dlq', maxReceiveCount: 5 } }), 'ap-northeast-1')))
      .toContain('pf-sqs-redrive-arn-region');
    expect(ids(diagnoseTemplate(queue({ RedriveAllowPolicy: { redrivePermission: 'byQueue', sourceQueueArns: ['arn:aws:sqs:us-east-1:123456789012:s'] } }), 'ap-northeast-1')))
      .toContain('pf-sqs-redrive-arn-region');
    expect(ids(diagnoseTemplate(queue({ RedriveAllowPolicy: { redrivePermission: 'byQueue', sourceQueueArns: ['arn:aws:sqs:ap-northeast-1:123456789012:s'] } }), 'ap-northeast-1')))
      .toHaveLength(0);
  });

  test('QueuePolicy.Queues: a literal ARN fires, Ref and URLs do not', () => {
    const pol = (queues: unknown[]) => ({ Resources: { ...Q, P: { Type: 'AWS::SQS::QueuePolicy', Properties: { Queues: queues, PolicyDocument: { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Principal: '*', Action: 'sqs:SendMessage', Resource: '*' }] } } } } });
    expect(ids(diagnoseTemplate(pol(['arn:aws:sqs:us-east-1:123456789012:q'])))).toContain('pf-sqs-queue-policy-queues');
    expect(ids(diagnoseTemplate(pol([])))).toContain('pf-sqs-queue-policy-queues');
    expect(ids(diagnoseTemplate(pol([{ Ref: 'Q' }, 'https://sqs.us-east-1.amazonaws.com/123456789012/q'])))).toHaveLength(0);
  });

  test('sns inline Topic.Subscription entries are judged like standalone subscriptions', () => {
    expect(ids(diagnoseTemplate(topic({ Subscription: [{ Protocol: 'sqs', Endpoint: 'https://not-an-arn' }] })))).toContain('pf-sns-subscription-endpoint');
    expect(ids(diagnoseTemplate(topic({ FifoTopic: true, TopicName: 't.fifo', Subscription: [{ Protocol: 'lambda', Endpoint: 'arn:aws:lambda:us-east-1:123456789012:function:f' }] })))).toContain('pf-sns-fifo-topic-protocol');
    expect(ids(diagnoseTemplate(topic({ Subscription: [{ Protocol: 'email', Endpoint: 'a@example.com', RawMessageDelivery: true }] })))).toContain('pf-sns-raw-message-delivery');
  });

  test('sns endpoint shapes per protocol; resource references are skipped', () => {
    const t = (p: string, e: unknown) => sub({ Protocol: p, Endpoint: e }, {}, Q);
    expect(ids(diagnoseTemplate(t('lambda', 'arn:aws:sqs:us-east-1:123456789012:q')))).toContain('pf-sns-subscription-endpoint');
    expect(ids(diagnoseTemplate(t('email', 'nope')))).toContain('pf-sns-subscription-endpoint');
    expect(ids(diagnoseTemplate(t('https', 'http://example.com')))).toContain('pf-sns-subscription-endpoint');
    expect(ids(diagnoseTemplate(t('sms', 'hello')))).toContain('pf-sns-subscription-endpoint');
    expect(ids(diagnoseTemplate(t('foo', 'x')))).toContain('pf-sns-subscription-endpoint');
    expect(ids(diagnoseTemplate(t('sqs', QARN)))).toHaveLength(0);
    expect(ids(diagnoseTemplate(t('application', 'arn:aws:sns:us-east-1:123456789012:endpoint/GCM/app/1')))).toHaveLength(0);
  });

  test('sns FIFO topic / FIFO queue pairing through literal ARNs', () => {
    const lit = (topicArn: string, endpoint: string) => ({ Resources: { S: { Type: 'AWS::SNS::Subscription', Properties: { TopicArn: topicArn, Protocol: 'sqs', Endpoint: endpoint } } } });
    expect(ids(diagnoseTemplate(lit('arn:aws:sns:us-east-1:123456789012:t', 'arn:aws:sqs:us-east-1:123456789012:q.fifo')))).toContain('pf-sns-fifo-queue-on-standard-topic');
    expect(ids(diagnoseTemplate(lit('arn:aws:sns:us-east-1:123456789012:t.fifo', 'arn:aws:sqs:us-east-1:123456789012:q')))).toHaveLength(0);
    expect(ids(diagnoseTemplate({ Resources: { S: { Type: 'AWS::SNS::Subscription', Properties: { TopicArn: 'arn:aws:sns:us-east-1:123456789012:t.fifo', Protocol: 'email', Endpoint: 'a@example.com' } } } }))).toContain('pf-sns-fifo-topic-protocol');
  });

  test('sns filter policy shapes', () => {
    const fp = (policy: unknown, scope?: string) => sub({ Protocol: 'sqs', Endpoint: QARN, FilterPolicy: policy, ...(scope ? { FilterPolicyScope: scope } : {}) }, {}, Q);
    expect(ids(diagnoseTemplate(fp({ a: 'x' })))).toContain('pf-sns-filter-policy');
    expect(ids(diagnoseTemplate(fp({ a: [] })))).toContain('pf-sns-filter-policy');
    expect(ids(diagnoseTemplate(fp({ a: [['x']] })))).toContain('pf-sns-filter-policy');
    expect(ids(diagnoseTemplate(fp({ a: { b: ['x'] } })))).toContain('pf-sns-filter-policy');
    expect(ids(diagnoseTemplate(fp({ a: { b: ['x'] } }, 'MessageBody')))).toHaveLength(0);
    expect(ids(diagnoseTemplate(fp(JSON.stringify({ a: ['1'], b: ['1'], c: ['1'], d: ['1'], e: ['1'], f: ['1'] }))))).toContain('pf-sns-filter-policy');
    expect(ids(diagnoseTemplate(fp({ a: ['1'] }, 'Foo')))).toContain('pf-sns-filter-policy');
  });

  test('sns delivery policy: phase total, min>max, backoff enum, topic-level http policy', () => {
    const dp = (policy: unknown) => sub({ Protocol: 'https', Endpoint: 'https://example.com/h', DeliveryPolicy: policy });
    expect(ids(diagnoseTemplate(dp({ healthyRetryPolicy: { minDelayTarget: 30, maxDelayTarget: 20, numRetries: 3 } })))).toContain('pf-sns-delivery-policy');
    expect(ids(diagnoseTemplate(dp({ healthyRetryPolicy: { minDelayTarget: 1, maxDelayTarget: 20, numRetries: 3, numNoDelayRetries: 4 } })))).toContain('pf-sns-delivery-policy');
    expect(ids(diagnoseTemplate(dp({ healthyRetryPolicy: { minDelayTarget: 1, maxDelayTarget: 20, numRetries: 3, backoffFunction: 'foo' } })))).toContain('pf-sns-delivery-policy');
    expect(ids(diagnoseTemplate(dp({ throttlePolicy: { maxReceivesPerSecond: 0 } })))).toContain('pf-sns-delivery-policy');
    expect(ids(diagnoseTemplate(topic({ DeliveryPolicy: { http: { defaultHealthyRetryPolicy: { minDelayTarget: 30, maxDelayTarget: 20, numRetries: 3 } } } })))).toContain('pf-sns-delivery-policy');
  });

  test('sns subscription redrive and region are bound to the deploy region', () => {
    const rd = (arn: string) => sub({ Protocol: 'sqs', Endpoint: QARN, RedrivePolicy: { deadLetterTargetArn: arn } }, {}, Q);
    expect(ids(diagnoseTemplate(rd('arn:aws:sqs:us-east-1:123456789012:dlq'), 'ap-northeast-1'))).toContain('pf-sns-subscription-redrive');
    expect(ids(diagnoseTemplate(rd('arn:aws:sqs:ap-northeast-1:123456789012:dlq'), 'ap-northeast-1'))).toHaveLength(0);
    expect(ids(diagnoseTemplate(sub({ Protocol: 'sqs', Endpoint: QARN, RedrivePolicy: {} }, {}, Q)))).toContain('pf-sns-subscription-redrive');
    expect(ids(diagnoseTemplate(sub({ Protocol: 'sqs', Endpoint: QARN, Region: 'us-east-1' }, {}, Q), 'ap-northeast-1'))).toContain('pf-sns-subscription-region');
    expect(ids(diagnoseTemplate(sub({ Protocol: 'sqs', Endpoint: QARN, Region: 'ap-northeast-1' }, {}, Q), 'ap-northeast-1'))).toHaveLength(0);
    expect(ids(diagnoseTemplate({ Resources: { S: { Type: 'AWS::SNS::Subscription', Properties: { TopicArn: 'arn:aws:sns:us-east-1:123456789012:t', Protocol: 'https', Endpoint: 'https://example.com/h', Region: 'eu-west-1' } } } }))).toContain('pf-sns-subscription-region');
  });

  test('sns topic attribute values and TopicPolicy.Topics', () => {
    expect(ids(diagnoseTemplate(topic({ SignatureVersion: '0' })))).toContain('pf-sns-topic-attribute-values');
    expect(ids(diagnoseTemplate(topic({ TracingConfig: 'Foo' })))).toContain('pf-sns-topic-attribute-values');
    expect(ids(diagnoseTemplate(topic({ FifoTopic: true, TopicName: 't.fifo', ArchivePolicy: { MessageRetentionPeriod: 366 } })))).toContain('pf-sns-fifo-only-attributes');
    expect(ids(diagnoseTemplate(topic({}, { P: { Type: 'AWS::SNS::TopicPolicy', Properties: { Topics: ['my-topic'], PolicyDocument: {} } } })))).toContain('pf-sns-topic-policy-topics');
  });
});
