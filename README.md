# cdk-preflight

**Catch deploy-time CloudFormation failures at `cdk synth` time.**

Some CloudFormation constraints are not expressed in resource provider schemas — they live only in documentation, in service API validation, or across multiple properties. Templates that violate them pass `cdk synth`, pass CloudFormation pre-deployment validation, and then fail minutes into a deployment, burning a rollback cycle.

cdk-preflight is a curated [Rego rule pack](docs/rules.md) for exactly those constraints. It injects the rules into the AWS CDK built-in CloudFormation validator (`aws-cdk-lib` >= 2.267.0), so violations surface at synth with construct-level traces — before you deploy.

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

`cdk synth` then reports violations like:

```text
WARNING idle_timeout.timeout_seconds is 5000 but must be between 1 and 4000 seconds (CloudFormation Validate)
   MyStack/Alb (Alb) aws-cdk-lib.aws_elasticloadbalancingv2.CfnLoadBalancer
   Acknowledge with 'CloudFormation-Validate::pf-elbv2-lb-idle-timeout-range'
```

## Failing the build

By default findings are warnings (matching the CDK built-in validator behavior). To make violations fail `cdk synth`:

```ts
Preflight.apply(app, { enforce: true });
```

| Option | Default | Effect |
|---|---|---|
| `enforce` | `false` | Violations of bundled rules fail synthesis instead of warning |
| `strict` | `false` | With `enforce`: also fail on error-class findings (`ERROR`/`FATAL`, e.g. `F3034`) of the built-in validation engine itself, which the CDK currently downgrades to warnings |
| `exclude` | `[]` | Rule ids to disable |
| `includeUpstreamPending` | `true` | Include rules already proposed to the upstream engine but not yet merged |

Individual findings can also be suppressed with the CDK acknowledge mechanism shown in the warning text.

## Bundled rules

See [docs/rules.md](docs/rules.md) for the generated rule table. Highlights:

- **ELBv2**: `idle_timeout` / `deregistration_delay` / `slow_start` attribute ranges (stringly-typed Key/Value attributes are invisible to schema validation)
- **IAM**: managed (6,144 chars) and inline (role/group/user) policy document size limits
- **CloudFront**: `MinTTL <= DefaultTTL <= MaxTTL` ordering, ACM certificates must live in `us-east-1`
- **Step Functions**: `StartAt`/`Next`/`Default`/`Choices` must reference defined states
- **EC2**: security group TCP/UDP port ranges and `FromPort <= ToPort`

## For AI agents

To add cdk-preflight to a CDK app:

1. `npm i -D cdk-preflight`
2. `npx cdk-preflight init` (finds the entry point via `cdk.json` and inserts `Preflight.apply(app)`; use `--dry-run` to preview)
3. Run `cdk synth` and read the warnings; each carries a rule id, a suggested fix, and a construct trace
4. If the user wants synthesis to fail on violations, change the call to `Preflight.apply(app, { enforce: true })`

The machine-readable findings are written to `cdk.out/validation-report.json` when synthesizing with `-c @aws-cdk/core:validationReportJson=true`.

## How it works

`Preflight.apply()` registers the rules with the CDK built-in `CloudFormationValidatePlugin` (the [cloudformation-validate](https://github.com/aws-cloudformation/cloudformation-validate) Rust/WASM engine that ships inside `aws-cdk-lib`). No extra binaries, no network access at synth time. In `enforce` mode the same engine is invoked through a dedicated validation plugin so that violations fail synthesis.

Constraints that *can* be expressed in schemas or generic engine rules are contributed upstream instead of living here; each rule's `meta.yaml` tracks its upstream status, and rules retire once the engine covers them.

## Requirements

- `aws-cdk-lib` >= 2.267.0 (the first release that bundles the built-in CloudFormation validator)

## Contributing

Rule authoring, the verification gates (including real-deploy reproduction), and the test layout are documented in [AGENTS.md](AGENTS.md) — written for AI coding agents and humans alike.

## License

Apache-2.0
