import * as fs from 'fs';
import { awscdk, github } from 'projen';
const project = new awscdk.AwsCdkConstructLibrary({
  author: 'Kazuho CryerShinozuka',
  authorAddress: 'malaysia.cryer@gmail.com',
  cdkVersion: '2.267.0',
  defaultReleaseBranch: 'main',
  jsiiVersion: '~5.8.0',
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
});

// rules/**/rule.rego + meta.yaml を src/rules.generated.ts に束ねる（コミット対象・鮮度は structure テストで担保）
const bundleRules = project.addTask('bundle-rules', {
  exec: 'ts-node --project test/tsconfig.json scripts/bundle-rules.ts',
});
project.preCompileTask.spawn(bundleRules);

// `npx cdk-preflight init` codemod
project.package.addBin({ 'cdk-preflight': 'lib/cli.js' });

// projen 0.103 は legacy .eslintrc.json を生成するが eslint は ^9 のため、
// v9 のレガシー設定サポートを明示的に有効化する
project.tasks.tryFind('eslint')!.env('ESLINT_USE_FLAT_CONFIG', 'false');

// 生成物とベンチの取り扱い
project.addPackageIgnore('/rules/');
project.addPackageIgnore('/bench/');
project.addPackageIgnore('/scripts/');

// ---- monthly-verify: 全ルールの fail テンプレートを毎月実機デプロイし、
// 制約ドリフト（ルール陳腐化）を検知する。doc-only ルールは対象外。
// 検証アカウントは workload-dev (502761806921)、既定リージョンは ap-northeast-1、
// us-east-1 実測ルールは meta.yaml の benchRegion に従う。
project.gitignore.addPatterns('/bench/out/');
const services = fs
  .readdirSync('rules', { withFileTypes: true })
  .filter((e) => e.isDirectory())
  .map((e) => e.name)
  .sort();
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
monthlyVerify.addJob('verify', {
  runsOn: ['ubuntu-latest'],
  timeoutMinutes: 300,
  permissions: {
    idToken: github.workflows.JobPermission.WRITE,
    contents: github.workflows.JobPermission.READ,
  },
  strategy: {
    failFast: false,
    maxParallel: 4, // VPC クォータ 5 に対し shard 内逐次 × 並列 4 で同時 VPC を上限未満に抑える
    matrix: { domain: { service: services } },
  },
  if: '${{ !inputs.service || inputs.service == matrix.service }}',
  steps: [
    checkoutStep,
    awsCredsStep,
    { name: 'Verify rules', run: 'bash bench/verify-all.sh ${{ matrix.service }}' },
    {
      name: 'Upload results',
      if: 'always()',
      uses: 'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a',
      with: { name: 'verify-${{ matrix.service }}', path: 'bench/out/' },
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
      with: { pattern: 'verify-*', path: 'bench/out/', 'merge-multiple': true },
    },
    { name: 'Sweep leftover stacks', run: 'bash bench/sweep.sh | tee bench/out/sweep.log' },
    { name: 'Report', run: 'bash bench/report.sh' },
  ],
});

project.synth();
