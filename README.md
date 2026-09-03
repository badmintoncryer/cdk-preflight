# cdk-preflight

**Catch deploy-time CloudFormation failures at `cdk synth` time.**

Some CloudFormation constraints are not expressed in resource provider schemas — they live only in documentation, in service API validation, or across multiple properties. Templates that violate them pass `cdk synth`, pass CloudFormation pre-deployment validation, and then fail minutes into a deployment, burning a rollback cycle.

cdk-preflight is a curated [Rego rule pack](docs/rules.md) for exactly those constraints, evaluated with the CloudFormation validation engine that ships inside `aws-cdk-lib` (>= 2.267.0). By default a violation **fails `cdk synth`** — a template that is known to fail at deploy time never leaves your machine.

Every bundled rule is backed by a `fail`/`pass` template pair, and the failure has been reproduced against real AWS (or is explicitly marked `doc-only`). Rules that the built-in validation engine already covers are deliberately **not** duplicated — a test suite enforces this.

## Quick start

```bash
npm i -D cdk-preflight
npx cdk-preflight init   # inserts Preflight.apply(app) into your CDK app
```

or add one line yourself:

```ts
import { Preflight } from 'cdk-preflight';

const app = new App();
Preflight.apply(app);
```

On violation, `cdk synth` fails with one error per finding, including the construct trace:

```text
ERROR idle_timeout.timeout_seconds is 5000 but must be between 1 and 4000 seconds (cdk-preflight)
   MyStack/Alb/Resource (Alb16C2F182) aws-cdk-lib.aws_elasticloadbalancingv2.CfnLoadBalancer

Synthesis finished with errors
```

## Observe-only mode

To roll the rules out gradually, start with `enforce: false`: findings then surface as synth **warnings** through the CDK built-in validator, with construct traces and per-finding acknowledgement:

```ts
Preflight.apply(app, { enforce: false });
```

```text
WARNING idle_timeout.timeout_seconds is 5000 but must be between 1 and 4000 seconds (CloudFormation Validate)
   MyStack/Alb (Alb) aws-cdk-lib.aws_elasticloadbalancingv2.CfnLoadBalancer
   Acknowledge with 'CloudFormation-Validate::pf-elbv2-lb-idle-timeout-range'
```

| Option | Default | Effect |
|---|---|---|
| `enforce` | `true` | Violations of bundled rules fail synthesis; set to `false` to only warn |
| `strict` | `false` | With `enforce`: also fail on error-class findings (`ERROR`/`FATAL`, e.g. `F3034`) of the built-in validation engine itself, which the CDK currently downgrades to warnings |
| `exclude` | `[]` | Rule ids to disable |
| `includeUpstreamPending` | `true` | Include rules already proposed to the upstream engine but not yet merged |

To opt out of a single rule, pass its id in `exclude`. In observe-only mode, individual findings can also be suppressed with the CDK acknowledge mechanism shown in the warning text.

## Bundled rules

See [docs/rules.md](docs/rules.md) for the generated rule table. Highlights:

- **ELBv2**: `idle_timeout` / `deregistration_delay` / `slow_start` attribute ranges (stringly-typed Key/Value attributes are invisible to schema validation)
- **IAM**: managed (6,144 chars) and inline (role/group/user) policy document size limits
- **CloudFront**: `MinTTL <= DefaultTTL <= MaxTTL` ordering, ACM certificates must live in `us-east-1`
- **Step Functions**: `Next`/`Default`/`Choices` must reference defined states (a dangling `StartAt` is already caught by the engine's built-in `E3601`)
- **EC2**: security group TCP/UDP port ranges and `FromPort <= ToPort`

## For AI agents

To add cdk-preflight to a CDK app:

1. `npm i -D cdk-preflight`
2. `npx cdk-preflight init` (finds the entry point via `cdk.json` and inserts `Preflight.apply(app)`; use `--dry-run` to preview)
3. Run `cdk synth`. Violations fail the synth with a validation report; each finding carries a rule id, the actual value, and a suggested fix
4. To fix a finding, prefer correcting the resource. To opt out instead: `exclude: ['<rule-id>']` disables one rule, `enforce: false` switches to warn-only reporting

The machine-readable findings are written to `cdk.out/validation-report.json` when synthesizing with `-c @aws-cdk/core:validationReportJson=true`.

### Report missed deploy errors

cdk-preflight only knows the failure modes it has benched. When a deploy fails on a constraint the pack should have caught, that report is how new rules get added — but at that moment cdk-preflight is out of the loop (it passed the synth), so the instruction has to already sit in your agent's context. Paste this into your repository's `AGENTS.md` (or `CLAUDE.md`):

```markdown
## cdk-preflight: report missed deploy errors

If `cdk deploy` fails even though `cdk synth` (with cdk-preflight enabled) passed,
and the failure is a service-side validation rejection — CREATE_FAILED/UPDATE_FAILED
with a 400-class message such as "Invalid request provided: ..." — cdk-preflight is
missing a rule. Report it:

1. Qualify first. NOT reportable: AccessDenied / permissions, service quotas,
   throttling, name conflicts with existing resources, stabilization timeouts.
2. Redact account-specific data (account IDs -> 123456789012, real ARNs/domains
   -> placeholders).
3. Search existing issues: https://github.com/badmintoncryer/cdk-preflight/issues
4. With your user's approval, open a "Missed deploy error" issue with the verbatim
   error message, the resource type, a minimal template snippet, and your
   aws-cdk-lib / cdk-preflight versions.
```

## How it works

`Preflight.apply()` evaluates the rules with the [cloudformation-validate](https://github.com/aws-cloudformation/cloudformation-validate) Rust/WASM engine that ships inside `aws-cdk-lib` — no extra binaries, no network access at synth time. In the default enforce mode the engine is invoked through a dedicated CDK validation plugin so that violations fail synthesis; with `enforce: false` the rules are instead injected into the CDK built-in `CloudFormationValidatePlugin` and reported as warnings.

Constraints that *can* be expressed in schemas or generic engine rules are contributed upstream instead of living here; each rule's `meta.yaml` tracks its upstream status, and rules retire once the engine covers them.

## Requirements

- `aws-cdk-lib` >= 2.267.0 (the first release that bundles the built-in CloudFormation validator)

## Contributing

Rule authoring, the verification gates (including real-deploy reproduction), and the test layout are documented in [AGENTS.md](AGENTS.md) — written for AI coding agents and humans alike.

## License

Apache-2.0
