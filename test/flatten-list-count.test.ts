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
 * 生のプロパティを `object.get` で読んでそのまま `count()` する経路（#272）もここに置く。
 * `count()` はオブジェクトに対して**キーの数**を返すので、`Fn::If` のマーカー
 * （`__conditional` / `__if_true` / `__if_false`）は「3 要素」、解決できない `Ref`
 * （`__dynamic`）は「1 要素」に化ける。`flatten_list` 越しと違って配列かどうかすら
 * 確かめていないぶん、こちらのほうが素通りしやすい。
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

describe('生のプロパティを count() する形 (#272)', () => {
  const pipeline = (props: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({
    ...extra,
    Resources: { P: { Type: 'AWS::CodePipeline::Pipeline', Properties: { RoleArn: 'arn:aws:iam::123456789012:role/r', Stages: [], ...props } } },
  });
  const variable = (i: number) => ({ Name: `v${i}`, DefaultValue: 'd' });

  describe('存在ゲート: count(object.get(...)) > 0', () => {
    // V1 パイプラインに Variables があると鳴る。Fn::If のマーカーはキーが 3 つあるので
    // 修正前は「変数が 3 つある」と読めて素通りしていた。
    const ID = 'pf-codepipeline-v1-variables';
    const v1 = (variables: unknown, extra?: Record<string, unknown>) =>
      pipeline({ PipelineType: 'V1', Variables: variables }, extra);

    test('リテラル 1 個は鳴る', () => {
      expect(fires(v1([variable(1)]), ID)).toBe(true);
    });

    test('リスト全体が Fn::If -> AWS::NoValue なら黙る（マーカーのキーを数えない）', () => {
      expect(fires(v1({ 'Fn::If': ['C', [variable(1)], NO_VALUE] }, { Conditions: COND }), ID)).toBe(false);
    });

    test('リスト全体が Ref でも鳴る（個数は不明でも「在る」ことは確か）', () => {
      expect(fires(v1({ Ref: 'Vars' }, { Parameters: { Vars: { Type: 'CommaDelimitedList' } } }), ID)).toBe(true);
    });
  });

  describe('閾値: count(object.get(...)) > N', () => {
    // 50 個までは通る。51 個目が Fn::If なら条件次第で消えるので数えてはいけない。
    const ID = 'pf-codepipeline-variables-max-50';
    const vars = (n: number) => Array.from({ length: n }, (_, i) => variable(i));

    test('リテラル 51 個は鳴る', () => {
      expect(fires(pipeline({ PipelineType: 'V2', Variables: vars(51) }), ID)).toBe(true);
    });

    test('リテラル 50 個は黙る', () => {
      expect(fires(pipeline({ PipelineType: 'V2', Variables: vars(50) }), ID)).toBe(false);
    });

    test('50 個 + Fn::If -> AWS::NoValue は黙る', () => {
      const withCond = [...vars(50), { 'Fn::If': ['C', variable(50), NO_VALUE] }];
      expect(fires(pipeline({ PipelineType: 'V2', Variables: withCond }, { Conditions: COND }), ID)).toBe(false);
    });
  });

  describe('等値: count(object.get(...)) != N', () => {
    // 予測スケーリングの MetricSpecifications はちょうど 1 個。条件つきの 2 個目を
    // 数えると「1 個であるべきなのに 2 個ある」と読めてしまう。
    const ID = 'pf-appautoscaling-predictive-metric-spec-single';
    const spec = (i: number) => ({ TargetValue: 50 + i, PredefinedMetricPairSpecification: { PredefinedMetricType: 'ECSServiceCPUUtilization' } });
    const policy = (specs: unknown, extra: Record<string, unknown> = {}) => ({
      ...extra,
      Resources: {
        P: {
          Type: 'AWS::ApplicationAutoScaling::ScalingPolicy',
          Properties: {
            PolicyName: 'p',
            PolicyType: 'PredictiveScaling',
            PredictiveScalingPolicyConfiguration: { MetricSpecifications: specs },
          },
        },
      },
    });

    test('リテラル 1 個は黙る', () => {
      expect(fires(policy([spec(0)]), ID)).toBe(false);
    });

    test('リテラル 2 個は鳴る', () => {
      expect(fires(policy([spec(0), spec(1)]), ID)).toBe(true);
    });

    test('1 個 + Fn::If -> AWS::NoValue は黙る（消えればちょうど 1 個）', () => {
      const withCond = [spec(0), { 'Fn::If': ['C', spec(1), NO_VALUE] }];
      expect(fires(policy(withCond, { Conditions: COND }), ID)).toBe(false);
    });
  });

  describe('マップのキー数: count(object.get(...)) > N', () => {
    // Attributes はリストではなく辞書。値が Fn::If -> AWS::NoValue ならキーごと消えるので、
    // 数える前に降りる（配列を要求する _pf_countable_items では通らない形）。
    const ID = 'pf-xray-samplingrule-attributes-max-5';
    const rule = (attributes: unknown, extra: Record<string, unknown> = {}) => ({
      ...extra,
      Resources: {
        R: {
          Type: 'AWS::XRay::SamplingRule',
          Properties: {
            SamplingRule: {
              RuleName: 'r',
              Priority: 9004,
              FixedRate: 0.05,
              ReservoirSize: 1,
              Host: '*',
              HTTPMethod: '*',
              URLPath: '*',
              ServiceName: '*',
              ServiceType: '*',
              ResourceARN: '*',
              Version: 1,
              Attributes: attributes,
            },
          },
        },
      },
    });
    const attrs = (n: number) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`a${i}`, 'v']));

    test('リテラル 6 個は鳴る', () => {
      expect(fires(rule(attrs(6)), ID)).toBe(true);
    });

    test('リテラル 5 個は黙る', () => {
      expect(fires(rule(attrs(5)), ID)).toBe(false);
    });

    test('5 個 + 値が Fn::If -> AWS::NoValue のキーは黙る', () => {
      expect(fires(rule({ ...attrs(5), a5: { 'Fn::If': ['C', 'v', NO_VALUE] } }, { Conditions: COND }), ID)).toBe(false);
    });
  });
});
