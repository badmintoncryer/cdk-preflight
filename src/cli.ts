#!/usr/bin/env node
/**
 * `npx cdk-preflight init` — 既存 CDK アプリに Preflight.apply(app) を挿入する codemod。
 * 人間にも AI エージェントにも同じ入口を提供する。
 */
import * as fs from 'fs';
import * as path from 'path';

/* eslint-disable no-console */

const USAGE = [
  'Usage: cdk-preflight init [--dry-run] [--dir <path>]',
  '',
  'Inserts `Preflight.apply(app)` into the CDK app entry point found via cdk.json.',
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

  let updated = src.replace(appLine, `${appLine}\nPreflight.apply(${appVar});`);
  updated = `import { Preflight } from 'cdk-preflight';\n${updated}`;

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

/* istanbul ignore next */
if (require.main === module) {
  process.exit(runCli(process.argv.slice(2)));
}
