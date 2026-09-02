import { awscdk } from 'projen';
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
  gitignore: ['*.js', '*.d.ts', '!test/.*.snapshot/**/*', '.tmp'],
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

project.synth();
