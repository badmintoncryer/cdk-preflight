/**
 * The cdk-preflight section of the pull request report Action (action.yml).
 */
// eslint-disable-next-line @typescript-eslint/no-require-imports
const { fromReport, fromLog, formatPreflight } = require('../action/preflight-report.cjs');

const REPORT = {
  pluginReports: [
    {
      pluginName: 'cdk-preflight',
      conclusion: 'failure',
      violations: [
        {
          ruleName: 'cdk-preflight::pf-alb-idle-timeout',
          description: 'idle_timeout.timeout_seconds is 5000 but must be between 1 and 4000 seconds',
          severity: 'error',
          violatingConstructs: [{ constructPath: 'App/Web/Alb/Resource' }],
        },
        {
          ruleName: 'pf-lambda-layer-cross-account-needs-permission',
          description: 'the layer is in another account | share it',
          severity: 'warning',
          violatingConstructs: [{ constructPath: 'App/Fn/Resource' }],
        },
      ],
    },
    { pluginName: 'other-plugin', violations: [{ ruleName: 'x', description: 'not ours', violatingConstructs: [{ constructPath: 'a' }] }] },
  ],
};

test('reads only cdk-preflight findings from validation-report.json', () => {
  expect(fromReport(REPORT)).toEqual([
    {
      severity: 'error',
      rule: 'pf-alb-idle-timeout',
      message: 'idle_timeout.timeout_seconds is 5000 but must be between 1 and 4000 seconds',
      path: 'App/Web/Alb/Resource',
    },
    {
      severity: 'warning',
      rule: 'pf-lambda-layer-cross-account-needs-permission',
      message: 'the layer is in another account | share it',
      path: 'App/Fn/Resource',
    },
  ]);
});

test('falls back to the synth log', () => {
  const log = [
    'ERROR idle_timeout.timeout_seconds is 5000 but must be between 1 and 4000 seconds (cdk-preflight)',
    '   MyStack/Alb/Resource (Alb16C2F182) aws-cdk-lib.aws_elasticloadbalancingv2.CfnLoadBalancer',
    'ERROR something else (other-plugin)',
    '   MyStack/X',
  ].join('\n');
  expect(fromLog(log)).toEqual([
    { severity: 'error', rule: '', message: 'idle_timeout.timeout_seconds is 5000 but must be between 1 and 4000 seconds', path: 'MyStack/Alb/Resource' },
  ]);
});

test('formats errors first and escapes table cells', () => {
  const md: string = formatPreflight(fromReport(REPORT), true, '');
  expect(md).toContain('### cdk-preflight: 1 deploy-time failure, 1 warning');
  expect(md.indexOf('❌')).toBeLessThan(md.indexOf('⚠️'));
  expect(md).toContain('`pf-alb-idle-timeout`');
  expect(md).toContain('in another account \\| share it');
});

test('a clean synth and a synth that broke for another reason', () => {
  expect(formatPreflight([], false, '')).toContain('no deploy-time failures found');
  const md: string = formatPreflight([], true, 'Error: Cannot find module');
  expect(md).toContain('`cdk synth` failed');
  expect(md).toContain('Cannot find module');
});
