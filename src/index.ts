import { Stage, Validations } from 'aws-cdk-lib';
import { IConstruct } from 'constructs';
import { engineVersion, installEnforceGate, isSuperseded, observePluginCached, PreflightEnforcePlugin } from './private/enforce';
import { BUNDLED_RULES } from './rules.generated';

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
   * Since the engine's own errors then fail synthesis, bundled rules that the
   * running engine already covers are skipped instead of being reported twice.
   * The same happens with `enforce: false`, and when the app sets the context
   * `@aws-cdk/core:validateAgainstDefaultRules: true`.
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
   * Rules marked `cfn-schema` are unaffected by this switch. CloudFormation's
   * own registry schema does reject those templates, but only with a
   * stack-level "Validation failed with 1 error(s)" that names no property, so
   * they keep earning their place at synth time and no engine release retires
   * them.
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
    const enforce = options.enforce ?? true;
    const strict = options.strict ?? false;
    // meta.yaml#supersededBy のルールは、このエンジンが同じ違反を自力で見つける。省くのは
    // 省いても止まり方が変わらないときだけ: observe（どちらも警告）、strict（組み込みの
    // ERROR/FATAL で止まる）、CDK 自身が組み込みを格下げしない設定のとき。既定の enforce では
    // CDK が組み込みの ERROR/FATAL を警告に落とすので、省くと synth が通ってしまう。
    const engineBlocks = !enforce || strict || cdkKeepsDefaultRuleErrors(scope);
    const version = engineBlocks ? engineVersion() : undefined;
    const selected = BUNDLED_RULES
      .filter((r) => (options.includeUpstreamPending ?? true) || r.upstream !== 'pending-engine')
      .filter((r) => !exclude.includes(r.id))
      .filter((r) => !isSuperseded(r, version));

    if (enforce) {
      Validations.of(scope).addPlugins(new PreflightEnforcePlugin(selected, strict));
      installEnforceGate(scope);
    } else {
      Validations.of(scope).addPlugins(observePluginCached(selected));
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

/**
 * CDK が組み込みエンジンの ERROR/FATAL を警告に落とさない設定か。判定は aws-cdk-lib 2.271.0 の
 * synthesis-validation と同じ: context `@aws-cdk/core:validateAgainstDefaultRules` が false 以外で
 * 設定されていて、かつ組み込みの自動登録が `CDK_VALIDATION=false` で止められていないこと。
 */
function cdkKeepsDefaultRuleErrors(scope: IConstruct): boolean {
  const raw = scope.node.tryGetContext('@aws-cdk/core:validateAgainstDefaultRules');
  return raw !== undefined && raw !== false && raw !== 'false' && process.env.CDK_VALIDATION !== 'false';
}
