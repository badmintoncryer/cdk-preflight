import { CloudFormationValidatePlugin, Stage, Validations } from 'aws-cdk-lib';
import { IConstruct } from 'constructs';
import { PreflightEnforcePlugin } from './private/enforce';
import { BUNDLED_LIBS, BUNDLED_RULES } from './rules.generated';

/**
 * Options for {@link Preflight.apply}.
 */
export interface PreflightOptions {
  /**
   * Rule ids to disable (see `Preflight.ruleIds()` or docs/rules.md).
   *
   * @default - all bundled rules are enabled
   */
  readonly exclude?: string[];

  /**
   * Fail synthesis when a bundled rule is violated.
   *
   * In the default (enforce) mode, cdk-preflight evaluates its rules with its
   * own validation plugin and a violation makes `cdk synth` fail — the whole
   * point of preflight checks is that a template known to fail at deploy time
   * never leaves your machine. Set `enforce: false` to observe first: findings
   * are then reported through the CDK built-in CloudFormation validator and
   * surface as synth warnings with construct traces, which can be muted per
   * finding via `Acknowledge with 'CloudFormation-Validate::<rule-id>'`.
   *
   * @default true
   */
  readonly enforce?: boolean;

  /**
   * In enforce mode, additionally fail synthesis on error-class findings
   * (severity ERROR/FATAL) of the built-in validation engine itself, e.g.
   * schema violations like `F3034`. This is the workaround for the CDK
   * behavior where all built-in findings are downgraded to warnings.
   *
   * Only effective in enforce mode (the default).
   *
   * @default false
   */
  readonly strict?: boolean;

  /**
   * Include rules that are marked `pending-engine` (candidates that have been
   * proposed to the upstream cloudformation-validate engine but are not merged
   * yet). Disable this if you run a newer engine that already covers them.
   *
   * @default true
   */
  readonly includeUpstreamPending?: boolean;
}

/**
 * cdk-preflight: catch deploy-time CloudFormation failures at synth time.
 *
 * Injects a curated Rego rule pack (constraints that resource provider schemas
 * do not express: doc-only value limits, cross-property and cross-resource
 * rules) into the AWS CDK built-in CloudFormation validator.
 *
 * @example
 * declare const app: App;
 * Preflight.apply(app);
 */
export class Preflight {
  /**
   * Register the cdk-preflight rules on an App or Stage.
   */
  public static apply(scope: IConstruct, options: PreflightOptions = {}): void {
    if (!Stage.isStage(scope)) {
      throw new Error('cdk-preflight: Preflight.apply() must be called on an App or a Stage');
    }
    const exclude = options.exclude ?? [];
    const unknown = exclude.filter((id) => !BUNDLED_RULES.some((r) => r.id === id));
    if (unknown.length > 0) {
      throw new Error(`cdk-preflight: unknown rule id(s) in exclude: ${unknown.join(', ')}`);
    }
    const selected = BUNDLED_RULES
      .filter((r) => (options.includeUpstreamPending ?? true) || r.upstream !== 'pending-engine')
      .filter((r) => !exclude.includes(r.id));

    if (options.enforce ?? true) {
      Validations.of(scope).addPlugins(new PreflightEnforcePlugin(selected, options.strict ?? false));
    } else {
      Validations.of(scope).addPlugins(new CloudFormationValidatePlugin({
        regoRules: [
          ...BUNDLED_LIBS.map((l) => ({ name: l.name, content: l.rego })),
          ...selected.map((r) => ({ name: r.id, content: r.rego })),
        ],
      }));
    }
  }

  /**
   * The ids of all bundled rules.
   */
  public static ruleIds(): string[] {
    return BUNDLED_RULES.map((r) => r.id);
  }

  private constructor() {}
}
