import * as path from 'path';
import type {
  IPolicyValidationContext,
  IPolicyValidationPlugin,
  PolicyValidationPluginReport,
  PolicyViolation,
} from 'aws-cdk-lib';
import type { BundledRuleData } from '../rules.generated';

/* eslint-disable @typescript-eslint/no-require-imports */

interface EngineDiagnostic {
  readonly ruleId: string;
  readonly severity: string;
  readonly message: string;
  readonly source?: string;
  readonly entity?: { readonly logicalId?: string };
  readonly propertyPath?: string;
  readonly documentationUrl?: string;
}

/**
 * enforce モード用の内部プラグイン。
 *
 * CDK 組み込みの CloudFormationValidatePlugin は全 finding を warning に丸めるため
 * （aws-cdk-lib 2.267.0 実測、昇格フラグも無効）、同じエンジンを直接呼び、
 * cdk-preflight のルール違反（および strict 時はエンジンのエラークラス）を
 * policy validation の失敗として報告して synth を止める。
 */
export class PreflightEnforcePlugin implements IPolicyValidationPlugin {
  public readonly name = 'cdk-preflight';

  constructor(
    private readonly rules: BundledRuleData[],
    private readonly strict: boolean,
  ) {}

  public validate(context: IPolicyValidationContext): PolicyValidationPluginReport {
    const engine = loadEngineCached();
    if (!engine) {
      // eslint-disable-next-line no-console
      console.error(
        'cdk-preflight: could not resolve @aws/cloudformation-validate; ' +
        'enforce mode is unavailable and no preflight checks were run. ' +
        'Install it as a devDependency or use the default (warn) mode.',
      );
      return { success: true, violations: [] };
    }

    const eng = regoEngineCached(engine, this.rules);
    const ours = new Set(this.rules.map((r) => r.id));
    const violations: PolicyViolation[] = [];

    for (const st of context.stackTemplates) {
      const report = eng.validateDetailed(new engine.TemplateFile(st.templatePath), {
        pseudoParameterOverrides: {
          accountId: context.accountId,
          region: context.region,
        },
      });
      for (const d of (report.diagnostics ?? []) as EngineDiagnostic[]) {
        const isOurs = d.source === 'CUSTOM' && ours.has(d.ruleId);
        const isStrictHit = this.strict
          && d.source !== 'CUSTOM'
          && (d.severity === 'ERROR' || d.severity === 'FATAL');
        if (!isOurs && !isStrictHit) continue;
        violations.push({
          ruleName: d.ruleId,
          description: d.message,
          severity: 'error',
          violatingResources: [{
            resourceLogicalId: d.entity?.logicalId ?? '(unknown)',
            templatePath: st.templatePath,
            locations: [d.propertyPath ?? '(template)'],
          }],
          ...(d.documentationUrl ? { ruleMetadata: { DocumentationUrl: d.documentationUrl } } : {}),
        });
      }
    }

    return { success: violations.length === 0, violations };
  }
}

// エンジン（WASM）の初期化は重いため、モジュールレベルでキャッシュする
let cachedEngineModule: any | false | undefined;
function loadEngineCached(): any | undefined {
  if (cachedEngineModule === undefined) {
    cachedEngineModule = loadEngine() ?? false;
  }
  return cachedEngineModule === false ? undefined : cachedEngineModule;
}

const regoEngineCache = new Map<string, any>();
function regoEngineCached(engineModule: any, rules: BundledRuleData[]): any {
  const key = rules.map((r) => r.id).join(',');
  if (!regoEngineCache.has(key)) {
    regoEngineCache.set(key, new engineModule.RegoEngine({
      customRules: rules.map((r) => ({ name: r.id, content: r.rego })),
    }));
  }
  return regoEngineCache.get(key);
}

/**
 * @aws/cloudformation-validate を解決する。
 * 通常は aws-cdk-lib が bundledDependencies として同梱しているコピーに乗る。
 * （テストからも利用するため export している）
 */
export function loadEngine(): any | undefined {
  try {
    return require('@aws/cloudformation-validate');
  } catch {
    // fall through
  }
  try {
    const libPkg = require.resolve('aws-cdk-lib/package.json');
    const engPkg = require.resolve('@aws/cloudformation-validate/package.json', {
      paths: [path.dirname(libPkg)],
    });
    return require(path.dirname(engPkg));
  } catch {
    return undefined;
  }
}
