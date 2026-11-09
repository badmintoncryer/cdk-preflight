#!/usr/bin/env node
/**
 * `npx cdk-preflight init` — 既存 CDK アプリに Preflight.apply(app) を挿入する codemod。
 * `npx cdk-preflight check <template...>` — CDK を使わずに書いた CloudFormation テンプレートを検査する。
 * 人間にも AI エージェントにも同じ入口を提供する。
 */
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

/* eslint-disable no-console */

const USAGE = [
  'Usage:',
  '  cdk-preflight init [--dry-run] [--dir <path>]',
  '      Insert `Preflight.apply(app)` into the CDK app entry point found via cdk.json.',
  '  cdk-preflight check [--warn] [--exclude <id,...>] [--region <r>] [--account <id>] [--output <dir>] <template...>',
  '      Check CloudFormation templates (JSON or YAML) written without CDK.',
  '      Exit 0 when nothing fails, 1 on findings, 2 when a template cannot be read.',
].join('\n');

/**
 * CLI 本体。テストから直接呼べるよう exit せず終了コードを返す。
 */
export function runCli(args: string[]): number {
  const cmd = args[0];
  if (cmd === undefined || cmd === '--help' || cmd === '-h') {
    console.log(USAGE);
    return 0;
  }
  if (cmd === 'check') {
    return runCheck(args.slice(1));
  }
  if (cmd !== 'init') {
    console.error(`cdk-preflight: unknown command "${cmd}"\n\n${USAGE}`);
    return 1;
  }
  const dry = args.includes('--dry-run');
  const dirIdx = args.indexOf('--dir');
  const cwd = dirIdx >= 0 && args[dirIdx + 1] ? path.resolve(args[dirIdx + 1]) : process.cwd();

  const cdkJsonPath = path.join(cwd, 'cdk.json');
  if (!fs.existsSync(cdkJsonPath)) {
    console.error(`cdk-preflight: no cdk.json found in ${cwd} (run inside a CDK app, or pass --dir)`);
    return 1;
  }
  const appCmd: string = JSON.parse(fs.readFileSync(cdkJsonPath, 'utf8')).app ?? '';
  const entryMatch = appCmd.match(/(\S+\.(?:ts|mts|cts|js|mjs|cjs))\b/);
  if (!entryMatch) {
    console.error(`cdk-preflight: could not locate an entry file in cdk.json "app": ${appCmd}`);
    return 1;
  }
  const entry = path.join(cwd, entryMatch[1]);
  if (!fs.existsSync(entry)) {
    console.error(`cdk-preflight: entry file not found: ${entry}`);
    return 1;
  }

  const src = fs.readFileSync(entry, 'utf8');
  if (src.includes('cdk-preflight')) {
    console.log(`cdk-preflight: ${entry} already references cdk-preflight — nothing to do`);
    return 0;
  }
  const appLineMatch = src.match(/^.*\bnew\s+(?:cdk\.)?App\s*\([^;\n]*\)\s*;?[^\S\n]*$/m);
  if (!appLineMatch) {
    console.error([
      `cdk-preflight: could not find \`new App(...)\` in ${entry}. Add manually:`,
      "  import { Preflight } from 'cdk-preflight';",
      '  Preflight.apply(app);',
    ].join('\n'));
    return 1;
  }
  const appLine = appLineMatch[0];
  const varMatch = appLine.match(/(?:const|let|var)\s+(\w+)\s*=/);
  const appVar = varMatch ? varMatch[1] : 'app';

  // 置換を関数で渡すのは、文字列だと App の行に含まれる `$&` などが展開されてしまうから。
  let updated = src.replace(appLine, () => `${appLine}\nPreflight.apply(${appVar});`);
  // CommonJS（`cdk init --language javascript` の形）に import を入れると ESM と判定され、
  // require が使えなくなってアプリが起動しない。
  const commonJs = /\.cjs$/.test(entry) || (/\.js$/.test(entry) && /\brequire\s*\(/.test(src) && !/^\s*import\s/m.test(src));
  const importLine = commonJs
    ? "const { Preflight } = require('cdk-preflight');"
    : "import { Preflight } from 'cdk-preflight';";
  // shebang は 1 行目、'use strict' は最初の文でなければ効かないので、その下に差し込む。
  const head = updated.match(/^(?:#![^\n]*\n)?(?:\s*(['"])use strict\1;?[^\S\n]*\n)?/)?.[0] ?? '';
  updated = `${head}${importLine}\n${updated.slice(head.length)}`;

  if (dry) {
    console.log(`--- ${entry} (dry run) ---\n${updated}`);
  } else {
    fs.writeFileSync(entry, updated);
    console.log(`cdk-preflight: updated ${entry}`);
  }
  console.log([
    '',
    'Next steps:',
    '  1. npm i -D cdk-preflight   (if not installed yet)',
    '  2. cdk synth                (violations fail the synth with a validation report)',
    '  3. Optional: Preflight.apply(app, { enforce: false }) to only warn instead of failing',
  ].join('\n'));
  return 0;
}

/**
 * `check`: 各テンプレートを cloudformation-include で 1 スタックずつ読み込んだ App を組み、
 * Preflight.apply してから synth する。ルールの評価は `cdk synth` と同じ経路を通るので、
 * 結果も出力も CDK アプリのときと変わらない。
 */
function runCheck(args: string[]): number {
  const files: string[] = [];
  const exclude: string[] = [];
  let warn = false;
  let region: string | undefined;
  let account: string | undefined;
  let output: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    const value = (): string | undefined => {
      const v = args[++i];
      if (v === undefined || v.startsWith('--')) {
        console.error(`cdk-preflight: ${a} needs a value\n\n${USAGE}`);
        return undefined;
      }
      return v;
    };
    if (a === '--warn') {
      warn = true;
    } else if (a === '--exclude' || a === '--region' || a === '--account' || a === '--output') {
      const v = value();
      if (v === undefined) return 2;
      if (a === '--exclude') exclude.push(...v.split(',').map((x) => x.trim()).filter(Boolean));
      else if (a === '--region') region = v;
      else if (a === '--account') account = v;
      else output = v;
    } else if (a.startsWith('--')) {
      console.error(`cdk-preflight: unknown flag "${a}"\n\n${USAGE}`);
      return 2;
    } else {
      files.push(a);
    }
  }
  if (files.length === 0) {
    console.error(`cdk-preflight: no template given\n\n${USAGE}`);
    return 2;
  }
  for (const f of files) {
    if (!fs.existsSync(f) || !fs.statSync(f).isFile()) {
      console.error(`cdk-preflight: template not found: ${f}`);
      return 2;
    }
  }

  // aws-cdk-lib は peerDependency。`init` だけ使う場合に読み込まずに済むよう、ここで初めて require する。
  /* eslint-disable @typescript-eslint/no-require-imports */
  const cdk: typeof import('aws-cdk-lib') = require('aws-cdk-lib');
  const { CfnInclude }: typeof import('aws-cdk-lib/cloudformation-include') = require('aws-cdk-lib/cloudformation-include');
  const { Preflight }: typeof import('./index') = require('./index');
  /* eslint-enable @typescript-eslint/no-require-imports */

  const outdir = output ? path.resolve(output) : fs.mkdtempSync(path.join(os.tmpdir(), 'cdk-preflight-check-'));
  const app = new cdk.App({ outdir });
  const env = region || account ? { region, account } : undefined;
  const used = new Set<string>();
  try {
    for (const f of files) {
      const id = stackId(f, used);
      const stack = new cdk.Stack(app, id, {
        env,
        // テンプレートに無い Rule や Parameter を足さない
        synthesizer: new cdk.DefaultStackSynthesizer({ generateBootstrapVersionRule: false }),
      });
      new CfnInclude(stack, 'Template', { templateFile: f });
    }
  } catch (e) {
    console.error(`cdk-preflight: cannot read template: ${(e as Error).message}`);
    return 2;
  }
  Preflight.apply(app, { enforce: !warn, exclude });

  try {
    app.synth();
  } catch (e) {
    // findings はライブラリ（CDK のフォーマッタ）が出力済み。レポートがあれば検査は走っている。
    if (fs.existsSync(path.join(outdir, 'validation-report.json'))) return 1;
    console.error(`cdk-preflight: ${(e as Error).message}`);
    return 2;
  }
  console.error(`cdk-preflight: checked ${files.length} template(s)${warn ? '' : ', no errors'}`);
  return 0;
}

/** テンプレートのファイル名からスタック名に使える一意な id を作る（`app.yaml` → `app`）。 */
function stackId(file: string, used: Set<string>): string {
  let base = path.basename(file, path.extname(file)).replace(/[^A-Za-z0-9-]/g, '-');
  if (!/^[A-Za-z]/.test(base)) base = `T${base}`;
  let id = base;
  for (let n = 2; used.has(id); n++) id = `${base}-${n}`;
  used.add(id);
  return id;
}

/* istanbul ignore next */
if (require.main === module) {
  process.exit(runCli(process.argv.slice(2)));
}
