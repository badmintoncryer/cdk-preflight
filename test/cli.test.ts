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
