# AGENTS.md — cdk-preflight

Guide for AI agents (and humans) working on this repository.

## What this package is

A data-first OSS: the product is the **rule pack** (`rules/`), not the loader. Rules are Rego documents evaluated by `@aws/cloudformation-validate` (the engine bundled inside `aws-cdk-lib` >= 2.267.0). The loader (`src/index.ts`) only selects rules and registers them with the CDK validation machinery.

Scope: **deploy-failure prevention only.** Security/compliance policies (cdk-nag, Control Tower proactive controls) are out of scope. A rule belongs here only if violating it makes an actual deployment fail.

## Design principles (do not violate)

1. **No duplication of the engine.** If the bundled engine already reports a constraint as ERROR/FATAL (schema check or built-in rule), we must not re-implement it. `test/rules.test.ts` enforces this mechanically ("does not duplicate a built-in blocker"). If that test fails for a new rule, the rule is unnecessary — delete it and record why in the PR.
2. **Every rule ships with proof.** `templates/fail.template.json` must violate exactly this rule; `templates/pass.template.json` must be clean. `meta.yaml#repro` records how the deploy-time failure was verified (`real-deploy` / `research-case` / `doc-only` — the last one requires an explanation in `evidence`).
3. **Rules graduate upstream.** Constraints expressible in schemas or generic engine rules should be PRed to [cloudformation-validate](https://github.com/aws-cloudformation/cloudformation-validate) (open an issue first). Track status in `meta.yaml#upstream` (`none` / `pending-engine` / `engine-pr` / `retired`). Shrinking this pack is success, not failure.
4. **Tests are the contract.** Never merge with a red test; never weaken an assertion to make it pass. New behavior needs a new test first.
5. **The boundary is the engine, not the CDK L2 layer.** Rules validate synthesized templates, so an L2 construct that validates (or structurally prevents) the same mistake does not make a rule redundant — L1 usage, escape hatches, `addPropertyOverride`, and externally generated templates all bypass L2. Overlapping an L2 guard is fine and expected; overlapping the bundled engine is forbidden (principle 1). When a rule does overlap L2, note it in the PR so reviewers can weigh the marginal value. See "Where this pack sits among validation layers" below.

## Where this pack sits among validation layers

Four other validation layers exist around a CDK app. Only one of them is a boundary for this pack; the relationships are:

| Layer | Runs at | Catches | Relation to this pack |
|---|---|---|---|
| CDK L2 construct validation | synth, only on that construct's prop path | per-construct guards (e.g. `Volume` iops checks, SNS auto-`.fifo`, Fargate hardcoding `awsvpc`) | **Not a boundary** (principle 5). Bypassed by L1 / escape hatches / external templates. Overlap allowed; record it in the PR |
| CDK L1 generated validators (`CfnXxx`) | synth, every CDK app | type and required-property checks only — never value ranges, patterns, or cross-field rules | **No practical overlap**: pack rules are value / cross-field constraints by construction |
| Bundled engine default rules (`@aws/cloudformation-validate`: SCHEMA / CFN_LINT / ENGINE) | synth, via this plugin | patched registry-schema ranges/patterns/enums + cfn-lint rules | **The hard boundary** (principle 1). If the bare engine reports ERROR/FATAL on the minimal violating template, the rule must not exist — enforced by the jest duplication guard |
| cfn-lint (external CLI) | outside the synth path (a separate CI step, if the user runs one) | near-parity with the bundled engine | **Not a boundary** — never disqualifies a rule. A check cfn-lint has but the engine lacks is an upstream-PR candidate *for the engine* (project policy: contribute to cloudformation-validate, not to cfn-lint) |
| CloudFormation server-side pre-deploy validation | CreateStack / UpdateStack / CreateChangeSet, before resources are touched | property syntax against RAW registry schemas for non-excluded types; resource name conflicts | **Effectively no overlap** with this pack's domain: ~420 resource types are excluded (IAM, EC2 SG, ECS, RDS, SFN, …) and raw schemas carry none of the doc-only limits — 0/16 real-world cases detected (measured 2026-09, cdk-validation-gap-research). Never a reason to reject a rule |
| CloudFormation + service APIs | deploy (CREATE/UPDATE) | everything else: cross-field rules, service-side business rules, quotas | **The target, not a duplicate to avoid.** A rule exists *iff* it front-runs a real deploy-time failure here; `meta.yaml#repro` (real-deploy gate) proves that equivalence |

Selection algorithm for a new rule, in order: (1) duplication guard — run the minimal violating template through the bare engine; any built-in ERROR/FATAL kills the candidate. A **WARN-class-only** engine finding (`W…`) does *not* kill it but marks a gray zone: the engine knows about the constraint and under-classifies it, so nothing blocks the deploy (`strict` promotes only ERROR/FATAL) — prefer filing an upstream severity issue, and if a stopgap rule ships anyway, mark it `upstream: pending-engine` so it retires with the upstream fix. (2) real-deploy gate — the fail template must actually fail CREATE with the predicted service error; a fail template that deploys kills the candidate (it happened: the "30-day minimum before STANDARD_IA" and the "4096-char ZipFile" constraints are documented but not enforced, so those rules were dropped). (3) L1/L2 coverage never disqualifies, only gets noted.

**A doc sentence is a hypothesis, not evidence.** The CloudFront survey (2026-09-02) put nine documented constraints through the gate and three of them deployed clean: `DefaultRootObject` "can't begin with a forward slash", `GeoRestriction.Locations` marked "Required: Conditional", and "a `CacheBehavior` must include either a `CachePolicyId` or `ForwardedValues`". All three are unambiguous prose in the CloudFormation reference; the API accepts all three. Shipping on the strength of the docs alone would have produced a third of that batch as false positives — synth failures on templates that deploy. Treat `doc-only` as reserved for constraints whose repro needs resources we cannot cheaply create (a validated ACM certificate, an owned domain), never as a shortcut for a constraint that simply has not been tried. When a repro comes back failing for a *different* reason than predicted — a foreign-account ARN, a CNAME rejected for ownership — that is not evidence either; rebuild the template until the service error names the constraint, or record the confound in `evidence`.

The same gate also corrects rules that are merely aimed slightly wrong. `pf-cloudfront-wafv2-webacl-scope` began life checking the ARN's region field; the service error (`Only global scoped ARNs are supported`) showed the real check is on the scope segment, which is what catches the realistic mistake — a REGIONAL web ACL created in us-east-1, where the region field looks perfectly correct.

### How much is an L2 overlap worth?

Principle 5 says an L2 guard never disqualifies a rule. It does not say every L2 check deserves a port — "allowed" and "worth it" are different questions, and the second one decides priority once rules are being added in bulk. Note that enforce is the default mode, so a false positive is a hard synth failure for users; the bar sits above "it is permitted".

Rank a candidate by **how easily the L2 guard is bypassed in normal use**, not by whether one exists.

**Highest value — CDK cannot validate it at all, by construction:**

- *Anything applied after the validation phase.* `validateTree` runs at `core/lib/private/synthesis.ts:48`, `synthesizeTree` at `:59`, and `addPropertyOverride` values are `deepMerge`d into the rendered resource inside `_toCloudFormation` (`core/lib/cfn-resource.ts:538`). A value injected by an override therefore passes through neither the L1 generated validator nor any `node.addValidation()` hook. The same ordering hides render-time transformations: IAM policy documents get a final minimization pass "just before rendering" (`aws-iam/lib/policy-document.ts:222`), so the final document size does not exist yet at validation time — and `aws-iam` accordingly has no size check at all.
- *Entry points the type system cannot describe.* Stringly-typed Key/Value attribute lists (ELBv2 `setAttribute` and friends): the type is `[{key, value}]`, so neither TypeScript nor an L2 prop can express "this key takes 30–900". `pf-elbv2-tg-slow-start-range` is the canonical case — the L2 prop `slowStart` does validate, but `setAttribute` is the normal way to set the other attributes, so the bypass is routine rather than exotic.
- *Opaque strings.* ASL passed via `DefinitionBody.fromString` / `fromFile`, policy document JSON, EventBridge patterns, metric expressions. The L2 accepts a string and does not parse it (and should not).
- *No L2 at the entry point at all.* Raw `CfnXxx` usage, `cloudformation-include`, migrate output, SAM-generated templates.

**Medium value — the information is usually missing rather than impossible to obtain:** cross-resource consistency where the counterpart was imported with `fromXxxArn`. The L2 holds only an ARN string; the template has both resources side by side with concrete values.

**Low value:** a constraint whose only entry point is a typed L2 prop that already validates it. Porting it buys coverage for hand-written L1 only, at full maintenance cost. Say so explicitly in the PR and expect a reviewer to ask why it is worth it.

**Do not repeat this mis-analysis:** "L2 cannot validate accumulated state because it validates in the constructor" is false — `node.addValidation()` hooks run during `validateTree`, after all mutation. Accumulation is not the structural wall. The wall is transformation that happens *after* `validateTree`.

## Repository layout

```
rules/<service>/<rule-id>/
  rule.rego                 # package cdk_preflight / import rego.v1 / violation contains make_diag_full(...)
  meta.yaml                 # id, service, resourceTypes, severity, title, constraintSource, upstream, repro
  templates/fail.template.json
  templates/pass.template.json
src/index.ts                # Preflight.apply / PreflightOptions (jsii surface — keep minimal)
src/private/enforce.ts      # enforce-mode plugin (calls the engine directly)
src/rules.generated.ts      # GENERATED from rules/ — never edit; run `npx projen bundle-rules`
scripts/bundle-rules.ts     # generator + structural validation
test/                       # 4 layers: rules / loader / structure / cli
bench/                      # real-deploy verification (needs an AWS account; not part of CI)
```

## Adding a rule (the pipeline)

1. Identify a constraint that fails only at deploy time (doc page, API error message, war story).
2. Create `rules/<service>/<rule-id>/` with all four files. Rego conventions:
   - `package cdk_preflight`, `import rego.v1`
   - Emit via `make_diag_full("<rule-id>", "ERROR", name, <property-path>, <message with actual value>, <fix>, <doc url>)`
   - Use the engine builtins (`resources_of_type`, `resolve`, `flatten_list`, `object.get`); guard numbers with `to_number` — it is undefined for non-numeric input, which safely skips tokens/refs.
   - The standard OPA `walk` builtin is NOT available in this engine. Write explicit traversals.
   - Helper rules must use a unique `_pf_<rule>_...` prefix (all rules share one package).
3. `npx projen bundle-rules` then `npx jest test/rules.test.ts test/structure.test.ts` — the duplication guard and fixture checks run here.
4. **Real-deploy gate**: `bash bench/verify-rule.sh <rule-id>` deploys the fail template (expects CREATE to fail; records the service error message) and, where cheap, the pass template (expects success, then deletes). Paste the observed error into `meta.yaml#repro.evidence` with the date. Only `doc-only` rules may skip this, with justification.
5. Update nothing else by hand — `docs/rules.md` and `src/rules.generated.ts` are generated.

## Commands

| Task | Command |
|---|---|
| Regenerate bundle + docs | `npx projen bundle-rules` |
| Unit tests | `npx jest` |
| Full build (jsii, lint, tests, package) | `npx projen build` |
| Real-deploy verification for one rule | `bash bench/verify-rule.sh <rule-id>` |

## Known engine facts (verified 2026-09-01, engine 1.7.0-beta)

- Custom rule diagnostics carry `source: "CUSTOM"`; schema checks are `SCHEMA` (e.g. `F3034`), cfn-lint-derived rules are `CFN_LINT`.
- The engine's bundled schemas are *patched* (e.g. SQS numeric ranges exist even though the raw registry schema lacks them). Always check what the engine already catches before writing a rule.
- The CDK plugin path downgrades every finding to a warning; `@aws-cdk/core:validateAgainstDefaultRules` does not promote them (confirmed inert in aws-cdk-lib 2.267.0). This is why `enforce` mode exists — and why it is the default (`enforce: false` opts into warn-only reporting).
- `to_number(null)` evaluates to `0` (not undefined). When reading optional numbers via `object.get(x, key, null)`, guard with `!= null` before `to_number`, or an absent property silently becomes 0 and can fire the rule (this bit the S3 lifecycle rules during development).
- The Rego parser rejects two-variable `some k, v in obj` **inside comprehensions** ("unexpected keyword `some`"; fine in rule bodies). Use `some k in object.keys(obj)` and index instead.
- The CDK renders `Acknowledge with 'cdk-preflight::<rule-id>'` under enforce-mode errors, but `Validations.acknowledge()` currently suppresses only annotation warnings (`validations.ts`: "Currently only annotation warnings can be suppressed") — the hint is inert for policy violations. The working opt-outs in enforce mode are `exclude` and `enforce: false`; do not document the acknowledge mechanism for enforce mode.
