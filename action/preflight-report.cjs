#!/usr/bin/env node
// Prints the cdk-preflight section of the pull request report as Markdown.
// Usage: preflight-report.cjs <cdk.out> <synth log> <synth exit code>
//
// The findings come from cdk.out/validation-report.json, which the CDK writes
// when the CLI handles the report itself. Without it (an older CLI, or a synth
// that stopped before writing it), they are read off the synth log instead.
'use strict';

const fs = require('fs');
const path = require('path');

const PLUGIN = 'cdk-preflight';

/** Findings of the cdk-preflight plugin in a validation report. */
function fromReport(report) {
  const out = [];
  for (const r of report?.pluginReports ?? []) {
    if (r?.pluginName !== PLUGIN) continue;
    for (const v of r.violations ?? []) {
      const constructs = v.violatingConstructs ?? [];
      const where = constructs.length > 0 ? constructs.map((c) => c.constructPath) : [''];
      for (const w of where) {
        out.push({
          severity: String(v.severity ?? 'error').toLowerCase(),
          rule: String(v.ruleName ?? '').replace(/^cdk-preflight::/, ''),
          message: String(v.description ?? ''),
          path: w ?? '',
        });
      }
    }
  }
  return out;
}

/**
 * Findings in a synth log: "ERROR <message> (cdk-preflight)" with the
 * construct path on the next line.
 */
function fromLog(log) {
  const lines = log.split(/\r?\n/);
  const out = [];
  lines.forEach((line, i) => {
    const m = line.match(/^\s*(ERROR|WARN|WARNING|INFO)\s+(.*)\s+\(cdk-preflight\)\s*$/);
    if (!m) return;
    const next = (lines[i + 1] ?? '').trim();
    out.push({
      severity: m[1].toLowerCase() === 'warning' ? 'warn' : m[1].toLowerCase(),
      rule: '',
      message: m[2],
      path: next.split(' ')[0] ?? '',
    });
  });
  return out;
}

function cell(s) {
  return String(s).replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');
}

/**
 * The Markdown section. synthFailed with no findings means the synth broke
 * for another reason, so the log tail is shown instead.
 */
function formatPreflight(findings, synthFailed, logTail) {
  const errors = findings.filter((f) => f.severity === 'error' || f.severity === 'fatal');
  const lines = [];
  if (findings.length === 0 && !synthFailed) {
    lines.push('### cdk-preflight: no deploy-time failures found', '');
    return lines.join('\n');
  }
  if (findings.length === 0) {
    lines.push('### cdk-preflight: `cdk synth` failed', '');
    lines.push('<details><summary>Synth log (last lines)</summary>', '', '```', logTail.trimEnd(), '```', '', '</details>', '');
    return lines.join('\n');
  }
  const warns = findings.length - errors.length;
  const title = errors.length > 0
    ? `${errors.length} deploy-time failure${errors.length === 1 ? '' : 's'}`
    : 'no deploy-time failures';
  lines.push(`### cdk-preflight: ${title}${warns > 0 ? `, ${warns} warning${warns === 1 ? '' : 's'}` : ''}`, '');
  lines.push('| | Construct | Finding |', '|---|---|---|');
  for (const f of [...errors, ...findings.filter((x) => !errors.includes(x))]) {
    const mark = errors.includes(f) ? '❌' : '⚠️';
    const rule = f.rule ? ` \`${f.rule}\`` : '';
    lines.push(`| ${mark} | \`${cell(f.path)}\` | ${cell(f.message)}${rule} |`);
  }
  lines.push('');
  return lines.join('\n');
}

function main(argv) {
  const [outDir, logFile, code] = argv;
  const log = logFile && fs.existsSync(logFile) ? fs.readFileSync(logFile, 'utf8') : '';
  let findings;
  try {
    findings = fromReport(JSON.parse(fs.readFileSync(path.join(outDir, 'validation-report.json'), 'utf8')));
  } catch {
    findings = fromLog(log);
  }
  const failed = code !== undefined && code !== '0';
  process.stdout.write(formatPreflight(findings, failed, log.split(/\r?\n/).slice(-40).join('\n')) + '\n');
  // 1 when the PR has findings that fail the deploy
  return findings.some((f) => f.severity === 'error' || f.severity === 'fatal') ? 1 : 0;
}

if (require.main === module) {
  process.exitCode = main(process.argv.slice(2));
}

module.exports = { fromReport, fromLog, formatPreflight };
