import * as path from 'path';
import type {
  IPolicyValidationContext,
  IPolicyValidationPlugin,
  PolicyValidationPluginReport,
  PolicyViolation,
} from 'aws-cdk-lib';
import { BUNDLED_LIBS, type BundledRuleData } from '../rules.generated';

/* eslint-disable @typescript-eslint/no-require-imports */
/* eslint-disable import/no-extraneous-dependencies -- @aws/cloudformation-validate は
   aws-cdk-lib 同梱コピーを動的解決する設計（依存には載せない）。README/AGENTS.md 参照 */

/**
 * The name of the generated Rego module that carries the deployment
 * environment into rule evaluation.
 */
export const DEPLOY_ENV_MODULE_NAME = '_pf_deploy_environment';

/**
 * Build the generated module defining `deploy_region` for the rule package.
 *
 * Rules must read it as `data.cdk_preflight.deploy_region` (never as a bare
 * variable): the data reference is simply undefined when the module is not
 * injected — the rule body fails and the rule skips — while a bare variable
 * would be a compile error. Injected by the enforce plugin when the app-level
 * region is concrete; the warn mode (CDK built-in plugin) never injects it,
 * so region-dependent rules only fire in enforce mode.
 */
export function deployEnvironmentModule(region: string): { name: string; content: string } {
  return {
    name: DEPLOY_ENV_MODULE_NAME,
    content: `package cdk_preflight\n\nimport rego.v1\n\ndeploy_region := ${JSON.stringify(region)}\n`,
  };
}

/**
 * Whether the region from the validation context is a concrete region name
 * (as opposed to undefined, an unresolved token, or a placeholder).
 */
export function isConcreteRegion(region: string | undefined): region is string {
  return typeof region === 'string' && /^[a-z]{2}(-[a-z]+)+-\d+$/.test(region);
}

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

    const region = isConcreteRegion(context.region) ? context.region : undefined;
    const eng = regoEngineCached(engine, this.rules, region);
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
function regoEngineCached(engineModule: any, rules: BundledRuleData[], region?: string): any {
  const key = `${region ?? ''}|${rules.map((r) => r.id).join(',')}`;
  if (!regoEngineCache.has(key)) {
    const customRules = [
      ...BUNDLED_LIBS.map((l) => ({ name: l.name, content: l.rego })),
      ...rules.map((r) => ({ name: r.id, content: r.rego })),
    ];
    if (region !== undefined) {
      customRules.push(deployEnvironmentModule(region));
    }
    regoEngineCache.set(key, new engineModule.RegoEngine({ customRules }));
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
