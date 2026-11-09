/**
 * `cdk-preflight init` codemod のテスト。
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { runCli } from '../src/cli';

function makeFixture(appTs: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cdk-preflight-cli-'));
  fs.mkdirSync(path.join(dir, 'bin'));
  fs.writeFileSync(path.join(dir, 'cdk.json'), JSON.stringify({ app: 'npx ts-node bin/app.ts' }));
  fs.writeFileSync(path.join(dir, 'bin', 'app.ts'), appTs);
  return dir;
}

const BASIC_APP = [
  "import * as cdk from 'aws-cdk-lib';",
  '',
  'const app = new cdk.App();',
  "new cdk.Stack(app, 'MyStack');",
  '',
].join('\n');

test('inserts import and Preflight.apply after new App(...)', () => {
  const dir = makeFixture(BASIC_APP);
  expect(runCli(['init', '--dir', dir])).toBe(0);
  const out = fs.readFileSync(path.join(dir, 'bin', 'app.ts'), 'utf8');
  expect(out.startsWith("import { Preflight } from 'cdk-preflight';\n")).toBe(true);
  expect(out).toContain('const app = new cdk.App();\nPreflight.apply(app);');
});

test('keeps the shebang on the first line', () => {
  const dir = makeFixture(`#!/usr/bin/env node\n${BASIC_APP}`);
  expect(runCli(['init', '--dir', dir])).toBe(0);
  const out = fs.readFileSync(path.join(dir, 'bin', 'app.ts'), 'utf8');
  expect(out.startsWith("#!/usr/bin/env node\nimport { Preflight } from 'cdk-preflight';\n")).toBe(true);
});

test('is idempotent', () => {
  const dir = makeFixture(BASIC_APP);
  expect(runCli(['init', '--dir', dir])).toBe(0);
  const once = fs.readFileSync(path.join(dir, 'bin', 'app.ts'), 'utf8');
  expect(runCli(['init', '--dir', dir])).toBe(0);
  const twice = fs.readFileSync(path.join(dir, 'bin', 'app.ts'), 'utf8');
  expect(twice).toBe(once);
});

test('handles a differently named variable', () => {
  const dir = makeFixture("import { App } from 'aws-cdk-lib';\nconst theApp = new App({ context: {} });\n");
  expect(runCli(['init', '--dir', dir])).toBe(0);
  const out = fs.readFileSync(path.join(dir, 'bin', 'app.ts'), 'utf8');
  expect(out).toContain('Preflight.apply(theApp);');
});

test('--dry-run does not modify the file', () => {
  const dir = makeFixture(BASIC_APP);
  expect(runCli(['init', '--dry-run', '--dir', dir])).toBe(0);
  expect(fs.readFileSync(path.join(dir, 'bin', 'app.ts'), 'utf8')).toBe(BASIC_APP);
});

test('fails cleanly without cdk.json', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cdk-preflight-cli-'));
  expect(runCli(['init', '--dir', dir])).toBe(1);
});

test('fails cleanly when new App(...) is missing', () => {
  const dir = makeFixture('console.log("no app here");\n');
  expect(runCli(['init', '--dir', dir])).toBe(1);
  expect(fs.readFileSync(path.join(dir, 'bin', 'app.ts'), 'utf8')).toBe('console.log("no app here");\n');
});

test('help and unknown commands', () => {
  expect(runCli([])).toBe(0);
  expect(runCli(['--help'])).toBe(0);
  expect(runCli(['bogus'])).toBe(1);
});

describe('JavaScript entry points', () => {
  function makeJsFixture(file: string, src: string): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cdk-preflight-cli-'));
    fs.mkdirSync(path.join(dir, 'bin'));
    fs.writeFileSync(path.join(dir, 'cdk.json'), JSON.stringify({ app: `node bin/${file}` }));
    fs.writeFileSync(path.join(dir, 'bin', file), src);
    return dir;
  }

  // `cdk init app --language javascript` が作る形。import を差し込むと ESM と判定されて
  // `require is not defined` で起動しなくなる。
  test('a CommonJS app gets a require, not an import', () => {
    const src = "#!/usr/bin/env node\n\nconst cdk = require('aws-cdk-lib');\nconst app = new cdk.App();\n";
    const dir = makeJsFixture('app.js', src);
    expect(runCli(['init', '--dir', dir])).toBe(0);
    const out = fs.readFileSync(path.join(dir, 'bin', 'app.js'), 'utf8');
    expect(out).not.toMatch(/^import /m);
    expect(out.startsWith("#!/usr/bin/env node\nconst { Preflight } = require('cdk-preflight');\n")).toBe(true);
    expect(out).toContain('const app = new cdk.App();\nPreflight.apply(app);');
  });

  test('a "use strict" directive stays the first statement', () => {
    const src = "'use strict';\nconst cdk = require('aws-cdk-lib');\nconst app = new cdk.App();\n";
    const dir = makeJsFixture('app.cjs', src);
    expect(runCli(['init', '--dir', dir])).toBe(0);
    const out = fs.readFileSync(path.join(dir, 'bin', 'app.cjs'), 'utf8');
    expect(out.startsWith("'use strict';\nconst { Preflight } = require('cdk-preflight');\n")).toBe(true);
  });

  test('an ES module app keeps getting an import', () => {
    const src = "import * as cdk from 'aws-cdk-lib';\nconst app = new cdk.App();\n";
    const dir = makeJsFixture('app.mjs', src);
    expect(runCli(['init', '--dir', dir])).toBe(0);
    const out = fs.readFileSync(path.join(dir, 'bin', 'app.mjs'), 'utf8');
    expect(out.startsWith("import { Preflight } from 'cdk-preflight';\n")).toBe(true);
  });
});

// String.prototype.replace は置換文字列の `$&` などを展開する
test('a $ in the App line is copied verbatim', () => {
  const dir = makeFixture("import { App } from 'aws-cdk-lib';\nconst app = new App({ context: { k: 'a$&b$1' } });\n");
  expect(runCli(['init', '--dir', dir])).toBe(0);
  const out = fs.readFileSync(path.join(dir, 'bin', 'app.ts'), 'utf8');
  expect(out).toContain("const app = new App({ context: { k: 'a$&b$1' } });\nPreflight.apply(app);");
});

describe('check', () => {
  const ALB = (timeout: string) => [
    'Resources:',
    '  Alb:',
    '    Type: AWS::ElasticLoadBalancingV2::LoadBalancer',
    '    Properties:',
    '      Subnets: [subnet-0123456789abcdef0, subnet-0123456789abcdef1]',
    '      LoadBalancerAttributes:',
    '        - Key: idle_timeout.timeout_seconds',
    `          Value: "${timeout}"`,
    '',
  ].join('\n');

  let dir: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'cdk-preflight-check-test-'));
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });
  afterEach(() => jest.restoreAllMocks());

  function template(name: string, body: string): string {
    const f = path.join(dir, name);
    fs.mkdirSync(path.dirname(f), { recursive: true });
    fs.writeFileSync(f, body);
    return f;
  }
  const out = () => ['--output', path.join(dir, 'out')];
  const report = () => fs.readFileSync(path.join(dir, 'out', 'validation-report.json'), 'utf8');

  test('exits 1 on a finding and prints it', () => {
    expect(runCli(['check', ...out(), template('app.yaml', ALB('5000'))])).toBe(1);
    expect(report()).toContain('pf-elbv2-lb-idle-timeout-range');
  });

  test('exits 0 on a clean template', () => {
    expect(runCli(['check', ...out(), template('app.yaml', ALB('60'))])).toBe(0);
  });

  test('reads JSON templates', () => {
    const json = JSON.stringify({
      Resources: {
        Alb: {
          Type: 'AWS::ElasticLoadBalancingV2::LoadBalancer',
          Properties: { LoadBalancerAttributes: [{ Key: 'idle_timeout.timeout_seconds', Value: '5000' }] },
        },
      },
    });
    expect(runCli(['check', ...out(), template('app.json', json)])).toBe(1);
  });

  test('--exclude skips a rule and --warn does not fail', () => {
    const f = template('app.yaml', ALB('5000'));
    expect(runCli(['check', ...out(), '--exclude', 'pf-elbv2-lb-idle-timeout-range', f])).toBe(0);
    expect(runCli(['check', '--output', path.join(dir, 'out2'), '--warn', f])).toBe(0);
  });

  test('checks several templates, even with the same file name', () => {
    const a = template('a/app.yaml', ALB('60'));
    const b = template('b/app.yaml', ALB('5000'));
    expect(runCli(['check', ...out(), a, b])).toBe(1);
    expect(report()).toContain('app-2/Template/Alb');
  });

  test('exits 2 on usage errors and unreadable templates', () => {
    expect(runCli(['check'])).toBe(2);
    expect(runCli(['check', '--bogus', 'x.yaml'])).toBe(2);
    expect(runCli(['check', '--exclude'])).toBe(2);
    expect(runCli(['check', path.join(dir, 'missing.yaml')])).toBe(2);
    expect(runCli(['check', ...out(), template('bad.yaml', 'Resources:\n  X: [unclosed\n')])).toBe(2);
  });
});
