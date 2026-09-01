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
- The CDK renders `Acknowledge with 'cdk-preflight::<rule-id>'` under enforce-mode errors, but `Validations.acknowledge()` currently suppresses only annotation warnings (`validations.ts`: "Currently only annotation warnings can be suppressed") — the hint is inert for policy violations. The working opt-outs in enforce mode are `exclude` and `enforce: false`; do not document the acknowledge mechanism for enforce mode.
