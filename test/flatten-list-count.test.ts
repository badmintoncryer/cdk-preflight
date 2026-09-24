/**
 * flatten_list() の要素数が合成済みテンプレートと合わない 2 経路の回帰プローブ（issue #258）。
 *
 * - `Fn::If` は真の枝に潰れる → デプロイ時に `AWS::NoValue` へ落ちる要素まで数える（過大カウント）
 * - `Ref` / `Fn::Split` はリスト全体を 1 要素として返す（過小カウント）
 *
 * どちらも「テンプレートからは実際の個数が分からない」形なので、個数を根拠に診断を出す
 * ルールは `rules/_lib/lists.rego` の述語で降りる。ここは黙ることと、**リテラルの個数では
 * 従来どおり鳴ること**（偽陰性を入れていないこと）の両方を押さえる。
 *
 * 各ルールの fail / pass フィクスチャは触っていないので、実機ゲートで取った証拠はそのまま有効。
 */
import { diagnoseTemplate } from './rule-table';

const fires = (tpl: unknown, ruleId: string): boolean =>
  diagnoseTemplate(tpl).some((d) => d.ruleId === ruleId);

const COND = { C: { 'Fn::Equals': ['a', 'b'] } };
const NO_VALUE = { Ref: 'AWS::NoValue' };

describe('flatten_list() の個数と実デプロイの個数がずれる形 (#258)', () => {
  describe('過大カウント: Fn::If -> AWS::NoValue の要素', () => {
    const ID = 'pf-codebuild-secondary-artifacts-max-12';
    const artifact = (i: number) => ({ ArtifactIdentifier: `a${i}`, Type: 'S3', Location: 'b', Name: 'n' });
    const project = (secondaryArtifacts: unknown, extra: Record<string, unknown> = {}) => ({
      ...extra,
      Resources: {
        P: {
          Type: 'AWS::CodeBuild::Project',
          Properties: {
            Artifacts: { Type: 'NO_ARTIFACTS' },
            Environment: { ComputeType: 'BUILD_GENERAL1_SMALL', Image: 'aws/codebuild/standard:7.0', Type: 'LINUX_CONTAINER' },
            ServiceRole: 'arn:aws:iam::123456789012:role/r',
            Source: { Type: 'NO_SOURCE' },
            SecondaryArtifacts: secondaryArtifacts,
          },
        },
      },
    });
    const real = (n: number) => Array.from({ length: n }, (_, i) => artifact(i));

    test('13 個のリテラルは鳴る', () => {
      expect(fires(project(real(13)), ID)).toBe(true);
    });

    test('12 個 + Fn::If の 1 個は黙る（条件が false なら 12 個でデプロイできる）', () => {
      expect(fires(project([...real(12), { 'Fn::If': ['C', artifact(99), NO_VALUE] }], { Conditions: COND }), ID)).toBe(false);
    });

    test('12 個のリテラルは黙る', () => {
      expect(fires(project(real(12)), ID)).toBe(false);
    });
  });

  describe('過小カウント: Ref / Fn::Split のリスト', () => {
    const ID = 'pf-msk-client-subnets-count';
    const cluster = (clientSubnets: unknown, extra: Record<string, unknown> = {}) => ({
      ...extra,
      Resources: {
        Cluster: {
          Type: 'AWS::MSK::Cluster',
          Properties: {
            ClusterName: 'pf258',
            KafkaVersion: '3.9.x',
            NumberOfBrokerNodes: 2,
            BrokerNodeGroupInfo: {
              InstanceType: 'kafka.t3.small',
              ClientSubnets: clientSubnets,
              StorageInfo: { EBSStorageInfo: { VolumeSize: 1 } },
            },
          },
        },
      },
    });

    test('リテラル 1 個は鳴る', () => {
      expect(fires(cluster(['subnet-00000000000000001']), ID)).toBe(true);
    });

    test('CommaDelimitedList の Ref は黙る（1 要素ではない）', () => {
      expect(fires(cluster({ Ref: 'Subnets' }, { Parameters: { Subnets: { Type: 'List<AWS::EC2::Subnet::Id>' } } }), ID)).toBe(false);
    });

    test('Fn::Split の結果は黙る', () => {
      expect(fires(cluster({ 'Fn::Split': [',', { Ref: 'S' }] }, { Parameters: { S: { Type: 'String' } } }), ID)).toBe(false);
    });

    test('リテラル 2 個は黙る', () => {
      expect(fires(cluster(['subnet-00000000000000001', 'subnet-00000000000000002']), ID)).toBe(false);
    });
  });

  describe('存在ゲート (count > 0) は Ref を「在る」として扱い続ける', () => {
    const ID = 'pf-eks-accessentry-node-type-forbids-groups';
    const entry = (kubernetesGroups: unknown, extra: Record<string, unknown> = {}) => ({
      ...extra,
      Resources: {
        AE: {
          Type: 'AWS::EKS::AccessEntry',
          Properties: {
            ClusterName: 'pf258',
            PrincipalArn: 'arn:aws:iam::123456789012:role/node',
            Type: 'EC2_LINUX',
            KubernetesGroups: kubernetesGroups,
          },
        },
      },
    });

    test('リテラルの 1 個は鳴る', () => {
      expect(fires(entry(['g']), ID)).toBe(true);
    });

    test('Ref のリストも鳴る（個数は不明でも「在る」ことは確か）', () => {
      expect(fires(entry({ Ref: 'G' }, { Parameters: { G: { Type: 'CommaDelimitedList' } } }), ID)).toBe(true);
    });

    test('Fn::If -> AWS::NoValue だけのリストは黙る', () => {
      expect(fires(entry([{ 'Fn::If': ['C', 'g', NO_VALUE] }], { Conditions: COND }), ID)).toBe(false);
    });

    test('リスト全体が Fn::If -> AWS::NoValue なら黙る', () => {
      expect(fires(entry({ 'Fn::If': ['C', ['g'], NO_VALUE] }, { Conditions: COND }), ID)).toBe(false);
    });
  });
  // flatten_list を通さず object.get で取り出した入れ子の配列も同じ穴を持つ。しかも
  // count() はオブジェクトのキー数を返すので、Fn::If のマーカーは「3 要素」に化ける。
  describe('入れ子から object.get で取り出した配列 (count はキー数を返す)', () => {
    const ID = 'pf-ecs-svc-connect-client-aliases-max';
    const service = (clientAliases: unknown, extra: Record<string, unknown> = {}) => ({
      ...extra,
      Resources: {
        S: {
          Type: 'AWS::ECS::Service',
          Properties: {
            Cluster: 'c',
            TaskDefinition: 'td',
            ServiceConnectConfiguration: { Enabled: true, Services: [{ PortName: 'api', ClientAliases: clientAliases }] },
          },
        },
      },
    });

    test('リテラル 2 個は鳴る', () => {
      expect(fires(service([{ Port: 80 }, { Port: 81 }]), ID)).toBe(true);
    });

    test('リテラル 1 個は黙る', () => {
      expect(fires(service([{ Port: 80 }]), ID)).toBe(false);
    });

    test('配列全体が Fn::If -> AWS::NoValue なら黙る（マーカーのキーを数えない）', () => {
      expect(fires(service({ 'Fn::If': ['C', [{ Port: 80 }], NO_VALUE] }, { Conditions: COND }), ID)).toBe(false);
    });

    test('1 個 + Fn::If -> AWS::NoValue は黙る', () => {
      expect(fires(service([{ Port: 80 }, { 'Fn::If': ['C', { Port: 81 }, NO_VALUE] }], { Conditions: COND }), ID)).toBe(false);
    });
  });
});
