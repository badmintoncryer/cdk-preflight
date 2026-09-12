import * as fs from 'fs';
import { awscdk, github, JsonPatch } from 'projen';
const project = new awscdk.AwsCdkConstructLibrary({
  author: 'Kazuho CryerShinozuka',
  authorAddress: 'malaysia.cryer@gmail.com',
  cdkVersion: '2.267.0',
  defaultReleaseBranch: 'main',
  jsiiVersion: '~6.0.0',
  name: 'cdk-preflight',
  projenrcTs: true,
  repositoryUrl: 'https://github.com/badmintoncryer/cdk-preflight.git',
  description: 'Catch deploy-time CloudFormation failures at synth time: a Rego rule pack for constraints that resource schemas miss, injected into the AWS CDK built-in validator',
  keywords: [
    'aws',
    'cdk',
    'aws-cdk',
    'validation',
    'cloudformation',
    'rego',
    'preflight',
    'linter',
    'policy-validation',
    'fail-fast',
  ],
  gitignore: ['*.js', '*.d.ts', '!test/.*.snapshot/**/*', '.tmp', '!/rules/logs/'],
  devDeps: ['yaml'],
  releaseToNpm: true,
  packageName: 'cdk-preflight',
  npmTrustedPublishing: true,
  workflowNodeVersion: '24',
  publishToPypi: {
    distName: 'cdk-preflight',
    module: 'cdk_preflight',
    trustedPublishing: true,
  },
  // AGENTS.md / llms.txt / 同梱スキルは製品の一部であり docs PR が日常的に発生するため、
  // projen 既定の feat/fix/chore に docs を加える
  githubOptions: {
    pullRequestLintOptions: {
      semanticTitleOptions: {
        types: ['feat', 'fix', 'chore', 'docs'],
      },
    },
  },
  // projen 既定の upgrade-main は peter-evans/create-pull-request に PAT
  // (PROJEN_GITHUB_TOKEN) が要り、未設定なので毎回 "Input 'token' not supplied" で
  // 落ちていた。PAT を持たない方針にしたので依存更新は Dependabot に寄せる。
  depsUpgrade: false,
  dependabot: true,
  dependabotOptions: {
    // versioningStrategy は projen 既定の LOCKFILE_ONLY のまま。package.json は
    // projen が .projenrc.ts から生成するので、直接書き換えられると build が落ちる。
    scheduleInterval: github.DependabotScheduleInterval.WEEKLY,
    labels: ['dependencies'],
    // PR 1 本にまとめる。ルール追加 PR と違って中身を個別に見る価値が薄い。
    groups: { all: { patterns: ['*'] } },
  },
});

// projen の Dependabot コンポーネントは npm しか出さないので、Actions も見てもらう。
project.tryFindObjectFile('.github/dependabot.yml')!.addOverride('updates.1', {
  'package-ecosystem': 'github-actions',
  'directory': '/',
  'schedule': { interval: 'weekly' },
  'labels': ['dependencies'],
  'groups': { all: { patterns: ['*'] } },
});

// rules/**/rule.rego + meta.yaml を src/rules.generated.ts に束ねる（コミット対象・鮮度は structure テストで担保）
const bundleRules = project.addTask('bundle-rules', {
  exec: 'ts-node --project test/tsconfig.json scripts/bundle-rules.ts',
});
project.preCompileTask.spawn(bundleRules);

// `npx cdk-preflight init` codemod
project.package.addBin({ 'cdk-preflight': 'lib/cli.js', 'cdkpf': 'lib/cli.js' });

// projen 0.103 は legacy .eslintrc.json を生成するが eslint は ^9 のため、
// v9 のレガシー設定サポートを明示的に有効化する
project.tasks.tryFind('eslint')!.env('ESLINT_USE_FLAT_CONFIG', 'false');

// 生成物とベンチの取り扱い
project.addPackageIgnore('/rules/');
project.addPackageIgnore('/bench/');
project.addPackageIgnore('/scripts/');
project.addPackageIgnore('/assets/');

// ---- monthly-verify: 全ルールの fail テンプレートを毎月実機デプロイし、
// 制約ドリフト（ルール陳腐化）を検知する。doc-only ルールは対象外。
// 検証アカウントは workload-dev (502761806921)、既定リージョンは ap-northeast-1、
// us-east-1 実測ルールは meta.yaml の benchRegion に従う。
project.gitignore.addPatterns('/bench/out/');

// sweep.sh の残骸回収は AWS 認証が要るので実機では回せない。スタブ版の自己チェックを
// テストに混ぜ、削除分岐が壊れたら CI で落ちるようにする（実 API は叩かない）。
project.testTask.exec('bash bench/sweep.test.sh');

// 公開される tarball の smoke test。テストは全部 src/ を import しているので、
// パッケージング側の壊れ（exports の漏れ、lib/rules.generated の解決失敗）は
// ここでしか出ない。ローカルでは `CI=true npx projen package:js && npx projen smoke`。
project.addTask('smoke', {
  description: 'Install the packed tarball into a scratch CDK app and check that enforce still fires',
  exec: 'bash scripts/smoke.sh dist/js/*.jsii.tgz',
});
// build の成果物（dist/js/*.tgz）を使い回す。checkout は dist を消さないよう .repo に出す。
project.buildWorkflow!.addPostBuildJob('package-smoke', {
  runsOn: ['ubuntu-latest'],
  permissions: { contents: github.workflows.JobPermission.READ },
  steps: [
    {
      name: 'Setup Node.js',
      uses: 'actions/setup-node@v7.0.0',
      with: { 'node-version': '24' },
    },
    github.WorkflowSteps.checkout({
      with: {
        path: '.repo',
        ref: '${{ github.event.pull_request.head.sha }}',
        repository: '${{ github.event.pull_request.head.repo.full_name }}',
      },
    }),
    { name: 'Smoke test the packed tarball', run: 'bash .repo/scripts/smoke.sh dist/js/*.jsii.tgz' },
  ],
});

// ルール不要化（エンジンが追いついた）の検知。AWS 不要・完全ローカル。
project.addTask('redundancy-scan', {
  description: 'List rules the bundled engine now blocks by itself (retirement candidates)',
  exec: 'ts-node --project test/tsconfig.json scripts/redundancy-scan.ts',
});
const services = fs
  .readdirSync('rules', { withFileTypes: true })
  .filter((e) => e.isDirectory() && !e.name.startsWith('_')) // rules/_lib holds shared helpers, not rules
  .map((e) => e.name)
  .sort();
// 1 ジョブに収まらないサービスはジョブを増やす方向にだけ割る（ジョブ内は逐次のままなので
// 同時 VPC 数は maxParallel を超えない）。認証は role-duration-seconds 4h、ジョブは
// timeoutMinutes 300 なので、1 シャード 3h 以内を目安にする。
// route53resolver: 実測 2026-09-11 us-east-1（fail-only）— エンドポイントが立ち切る 10 本が
// 337 秒/本、エンドポイント自身が違反で即拒否される 19 本が 225 秒/本、残り 33 本が 50 秒/本。
// 62 本を逐次で回すと 2.6h で、INCONCLUSIVE のリトライが重なると 4h に触れる。3 分割で 1 本 55 分前後。
const shards: Record<string, number> = { route53resolver: 3 };
services.forEach((s) => {
  // verify-all.sh は "<service>.<i>of<n>" を '.' で切って解釈する
  if (s.includes('.')) throw new Error(`service directory name must not contain a dot: ${s}`);
});
const shardedServices = services.flatMap((s) =>
  shards[s] ? Array.from({ length: shards[s] }, (_, i) => `${s}.${i + 1}of${shards[s]}`) : [s],
);
const monthlyVerify = new github.GithubWorkflow(project.github!, 'monthly-verify', {
  limitConcurrency: true,
  concurrencyOptions: { group: 'monthly-verify', cancelInProgress: false },
});
monthlyVerify.on({
  schedule: [{ cron: '0 18 1 * *' }], // 毎月1日 18:00 UTC = JST 2日 3:00
  workflowDispatch: {
    inputs: {
      service: {
        description: 'verify a single service (empty = all)',
        required: false,
        type: 'string',
        default: '',
      },
    },
  },
});
const verifyRole = 'arn:aws:iam::502761806921:role/cdkpf-monthly-verify';
const checkoutStep: github.workflows.JobStep = {
  uses: 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
};
const awsCredsStep: github.workflows.JobStep = {
  name: 'Configure AWS credentials',
  uses: 'aws-actions/configure-aws-credentials@v4',
  with: {
    'role-to-assume': verifyRole,
    'aws-region': 'ap-northeast-1',
    'role-duration-seconds': 14400,
  },
};
// ジョブレベル if では matrix コンテキストが使えないため、
// 単一サービス dispatch の絞り込みは matrix 自体を plan ジョブで組んで実現する
monthlyVerify.addJob('plan', {
  runsOn: ['ubuntu-latest'],
  permissions: {},
  outputs: { services: { stepId: 'plan', outputName: 'services' } },
  steps: [
    {
      id: 'plan',
      name: 'Compute service matrix',
      run: [
        'if [ -n "${{ inputs.service }}" ]; then',
        // サービス名だけを渡されたらそのサービスのシャードに展開する（知らない名前はそのまま通す）
        '  python3 -c \'import json,sys; a=json.loads(sys.argv[1]); s=sys.argv[2];' +
          ' print("services="+json.dumps([x for x in a if x==s or x.startswith(s+".")] or [s]))\'' +
          ` '${JSON.stringify(shardedServices)}' "\${{ inputs.service }}" >> "$GITHUB_OUTPUT"`,
        'else',
        `  echo 'services=${JSON.stringify(shardedServices)}' >> "$GITHUB_OUTPUT"`,
        'fi',
      ].join('\n'),
    },
  ],
});
monthlyVerify.addJob('verify', {
  runsOn: ['ubuntu-latest'],
  needs: ['plan'],
  timeoutMinutes: 300,
  permissions: {
    idToken: github.workflows.JobPermission.WRITE,
    contents: github.workflows.JobPermission.READ,
  },
  strategy: {
    failFast: false,
    maxParallel: 4, // VPC クォータ 5 に対し shard 内逐次 × 並列 4 で同時 VPC を上限未満に抑える
    matrix: {
      domain: { service: '${{ fromJSON(needs.plan.outputs.services) }}' as unknown as string[] },
    },
  },
  steps: [
    checkoutStep,
    awsCredsStep,
    { name: 'Verify rules', run: 'bash bench/verify-all.sh ${{ matrix.service }}' },
    {
      name: 'Upload results',
      if: 'always()',
      uses: 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a',
      with: { name: 'verify-${{ matrix.service }}', path: 'bench/out/\nbench/logs/' },
    },
  ],
});
monthlyVerify.addJob('report', {
  runsOn: ['ubuntu-latest'],
  needs: ['verify'],
  if: 'always()',
  permissions: {
    idToken: github.workflows.JobPermission.WRITE,
    contents: github.workflows.JobPermission.READ,
    issues: github.workflows.JobPermission.WRITE,
  },
  env: { GH_TOKEN: '${{ github.token }}' },
  steps: [
    checkoutStep,
    awsCredsStep,
    {
      name: 'Download results',
      uses: 'actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c',
      with: { 'pattern': 'verify-*', 'path': 'bench/out/', 'merge-multiple': true },
    },
    { name: 'Sweep leftover stacks', run: 'bash bench/sweep.sh | tee bench/out/sweep.log' },
    {
      name: 'Setup node',
      uses: 'actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020',
      with: { 'node-version': '20' },
    },
    { name: 'Install', run: 'yarn install --check-files --frozen-lockfile' },
    // 不要化スキャン: 実機ではなく同梱エンジンに fail テンプレートを掛け直し、
    // 組み込みが止めるようになったルール（＝退役候補）を洗い出す
    { name: 'Redundancy scan', run: 'npx projen redundancy-scan | tee bench/out/redundancy.log' },
    { name: 'Report', run: 'bash bench/report.sh' },
  ],
});

// release の `git diff --exit-code` は、ルール追加 PR が並行マージされると必ず落ちる。
// 各ブランチは自分の base で README のルール数バッジを再生成するので、2 本続けて
// マージされた main では README だけが古い数字で残る（例: #167 と #169 → 1849 vs 1918）。
//
// そこで release 本体の前に bundle-rules を回してローカル commit だけ作り、push は
// ジョブの最後まで遅らせる。release ステップ時点で tree は綺麗なので diff チェックを
// 通り、リモートの main は未変更なので projen 既定のガード
// （latest_commit == github.sha）も通って publish がそのまま走る。
// push が GITHUB_TOKEN で release を再トリガーしないことが、ここでは逆に好都合
// （二重 release にならない）。PAT は不要。
const selfMutationCommit: github.workflows.JobStep = {
  name: 'Self mutation',
  run: [
    'npx projen bundle-rules',
    'if ! git diff --ignore-space-at-eol --exit-code; then',
    '  git add -A',
    '  git commit -m "chore: self mutation"',
    'fi',
  ].join('\n'),
};
// ponytail: タグは projen 生成のまま $GITHUB_SHA（= self mutation の 1 つ手前）を指す。
// ずれるのは README のバッジ 1 行だけなので放置。気になったら release_github の
// --target も差し替える。
const selfMutationPush: github.workflows.JobStep = {
  name: 'Push self mutation',
  // ジョブ中に人間が main を進めると push が弾かれる。バッジ再生成は冪等なので
  // 次の release が同じ差分を作り直す。publish 済みのランを赤くする方が損。
  run: 'git push origin HEAD:${{ github.ref_name }} || echo "push rejected (main moved) - the next release redoes it"',
};
// steps[4] = projen 生成の `release` ステップ。その直前に commit を差し込み、
// push は steps の末尾に足す。projen 更新でステップ構成が変わったら添字を見直すこと。
project.github!.tryFindWorkflow('release')!.file!.patch(
  JsonPatch.add('/jobs/release/steps/4', selfMutationCommit),
  JsonPatch.add('/jobs/release/steps/-', selfMutationPush),
);

project.synth();
