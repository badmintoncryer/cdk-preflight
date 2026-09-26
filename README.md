<p align="center">
  <img src="https://raw.githubusercontent.com/badmintoncryer/cdk-preflight/main/assets/logo.png" alt="cdk-preflight" width="104" height="104">
</p>

<h1 align="center">cdk-preflight</h1>

<p align="center">
  <strong>Catch deploy-time CloudFormation failures at <code>cdk synth</code> time.</strong>
</p>

<p align="center">
  <a href="https://github.com/badmintoncryer/cdk-preflight/actions/workflows/monthly-verify.yml"><img src="https://github.com/badmintoncryer/cdk-preflight/actions/workflows/monthly-verify.yml/badge.svg" alt="monthly real-deploy verification"></a>
  <a href="https://www.npmjs.com/package/cdk-preflight"><img src="https://img.shields.io/npm/v/cdk-preflight.svg" alt="npm version"></a>
  <a href="https://www.npmjs.com/package/cdk-preflight"><img src="https://img.shields.io/npm/dt/cdk-preflight.svg" alt="npm total downloads"></a>
  <a href="docs/rules.md"><img src="https://img.shields.io/badge/rules-3107-blue" alt="3107 bundled rules"></a>
</p>

Some CloudFormation constraints are not expressed in resource provider schemas — they live only in documentation, in service API validation, or across multiple properties. Templates that violate them pass `cdk synth`, pass CloudFormation pre-deployment validation, and then fail minutes into a deployment, burning a rollback cycle.

cdk-preflight is a curated [Rego rule pack](docs/rules.md) for exactly those constraints, evaluated with the CloudFormation validation engine that ships inside `aws-cdk-lib` (>= 2.267.0). By default a violation **fails `cdk synth`** — a template that is known to fail at deploy time never leaves your machine.

The pack aims at **every deploy-time failure that no existing CDK mechanism already catches** — nothing narrower. Every bundled rule is backed by a `fail`/`pass` template pair, and the failure has been reproduced against real AWS. The handful of rules that could not be reproduced are marked `doc-only` and report as **warnings**, as does a rule whose remaining false positives cannot be told from the template (a cross-account Lambda layer the owner may have shared): they show up in the validation report but never fail synth. Rules that the built-in validation engine already covers are deliberately **not** duplicated — a test suite enforces this.

> **Requires `aws-cdk-lib` >= 2.267.0** (released 2026-08-27) — the first release that bundles
> the CloudFormation validation engine. On older versions the rules cannot run at all.

## Quick start

```bash
npm i -D cdk-preflight
npx cdkpf init   # inserts Preflight.apply(app) into your CDK app
                         # (`npx cdkpf init` is the same command, shorter)
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

## What it catches

Four ordinary-looking snippets. All of them pass `cdk synth` and CloudFormation
pre-deployment validation, and all of them fail minutes into a deployment:

```ts
// 1) pf-iam-inline-policy-size — enumerate buckets, grant each one, blow past 10,240 chars
//    "Maximum policy size of 10240 bytes exceeded for role IngestRole"
//    (via role.addToPolicy the CDK auto-splits into managed policies instead,
//     and you hit the 6,144-char limit as pf-iam-managed-policy-size)
new iam.Policy(this, 'IngestPolicy', {
  roles: [role],
  statements: [new iam.PolicyStatement({
    actions: ['s3:GetObject', 's3:ListBucket'],
    resources: Array.from({ length: 200 },
      (_, i) => `arn:aws:s3:::data-lake-landing-zone-${i}/year=*/month=*/*`),
  })],
});

// 2) pf-lambda-env-size — a config blob in the environment, over the 4KB total
//    "Lambda was unable to configure your environment variables because the
//     environment variables you have provided exceeded the 4KB limit"
new lambda.Function(this, 'Fn', {
  runtime: lambda.Runtime.NODEJS_22_X,
  handler: 'index.handler',
  code: lambda.Code.fromInline('exports.handler = async () => {};'),
  environment: { FEATURE_FLAGS: JSON.stringify(bigFeatureFlagMap) },
});

// 3) pf-sfn-asl-missing-state (+ pf-sfn-asl-unreachable-state) — a typo in a state name
//    "Invalid State Machine Definition: 'MISSING_TRANSITION_TARGET: ...'"
new sfn.StateMachine(this, 'Pipeline', {
  definitionBody: sfn.DefinitionBody.fromString(JSON.stringify({
    StartAt: 'Validate',
    States: {
      Validate: { Type: 'Pass', Next: 'Transform' },
      Trasform: { Type: 'Pass', End: true },   // typo: Transform
    },
  })),
});

// 4) pf-logs-filter-pattern-bracket — a filter pattern opened with '[' and never closed
//    "If a filter pattern starts with '[' it must end with ']'"
new logs.MetricFilter(this, 'ErrorFilter', {
  logGroup,
  metricNamespace: 'Pipeline',
  metricName: 'Errors',
  filterPattern: logs.FilterPattern.literal('[time, level=ERROR, msg'),
});
```

None of these are type errors, so the L2 constructs accept them; none of them are
expressible in a resource schema, so CloudFormation accepts the template. With
`Preflight.apply(app)` in place they fail `cdk synth` instead.

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

> **Known limitation with stages.** The AWS CDK CLI drops validation findings for stacks nested in a `Stage`
> before printing them, so in observe-only mode those findings appear **only** in `cdk.out/validation-report.json`
> and never on the console. Enforce mode is not affected: cdk-preflight reports such findings itself and fails
> synthesis. This is a CLI-side bug (present since aws-cdk 2.1128.1), not a rule evaluation problem.

> **If the rules cannot run, the build stops.** When the evaluation engine fails on a template (a rule pack that
> does not compile, an engine bug), enforce mode reports it as a violation named `pf-engine-error` and fails
> synthesis for that stack instead of passing green with no rule having run. The other stacks keep their rules.
> `pf-engine-error` is not a bundled rule and cannot be `exclude`d; `enforce: false` unblocks the build if you
> need one.

| Option | Default | Effect |
|---|---|---|
| `enforce` | `true` | Violations of bundled rules fail synthesis; set to `false` to only warn |
| `strict` | `false` | With `enforce`: also fail on error-class findings (`ERROR`/`FATAL`, e.g. `F3034`) of the built-in validation engine itself, which the CDK currently downgrades to warnings |
| `exclude` | `[]` | Rule ids to disable |
| `includeUpstreamPending` | `true` | Include rules already proposed to the upstream engine but not yet merged |

To opt out of a single rule everywhere, pass its id in `exclude`. To suppress a
single *finding* on one construct, acknowledge it — this works in both modes, the
id prefix just differs (`cdk-preflight::` when enforcing, `CloudFormation-Validate::`
in observe-only, as printed in the warning text):

```ts
cdk.Validations.of(errorFilter).acknowledge({
  id: 'cdk-preflight::pf-logs-filter-pattern-bracket',
  reason: 'log group is written by a legacy producer; pattern is fixed upstream',
});
```

## Bundled rules

See [docs/rules.md](docs/rules.md) for the generated rule table.

<!-- supported-resources:start -->
<details>
<summary><b>405 resource types across 74 services</b> — click to expand</summary>

Resource names are relative to `AWS::<Service>::`; the number in parentheses is how many rules target that type.

| Service | Resource types |
|---|---|
| **(any resource type)** | `*` (14) |
| **ApiGateway** | `ApiKey` (1), `Authorizer` (5), `Deployment` (1), `DocumentationPart` (1), `DomainName` (4), `GatewayResponse` (1), `Method` (12), `Model` (3), `Resource` (1), `RestApi` (4), `Stage` (9), `UsagePlan` (5), `VpcLink` (1) |
| **ApiGatewayV2** | `Api` (5), `Authorizer` (11), `DomainName` (3), `Integration` (15), `IntegrationResponse` (1), `Model` (2), `Route` (6), `RouteResponse` (2), `Stage` (4), `VpcLink` (1) |
| **ApplicationAutoScaling** | `ScalableTarget` (19), `ScalingPolicy` (30) |
| **AppSync** | `Api` (7), `ApiCache` (4), `ApiKey` (2), `ChannelNamespace` (5), `DataSource` (15), `DomainName` (1), `FunctionConfiguration` (24), `GraphQLApi` (16), `GraphQLSchema` (12), `Resolver` (32), `SourceApiAssociation` (3) |
| **APS** | `AnomalyDetector` (9), `ResourcePolicy` (5), `RuleGroupsNamespace` (10), `Workspace` (12) |
| **Athena** | `DataCatalog` (6), `WorkGroup` (8) |
| **AutoScaling** | `AutoScalingGroup` (38), `LifecycleHook` (8), `ScalingPolicy` (41), `ScheduledAction` (13), `WarmPool` (4) |
| **Backup** | `BackupPlan` (12), `BackupSelection` (4), `BackupVault` (3), `Framework` (3), `LogicallyAirGappedBackupVault` (2), `ReportPlan` (2), `RestoreTestingPlan` (5), `RestoreTestingSelection` (3) |
| **Batch** | `ComputeEnvironment` (40), `ConsumableResource` (2), `JobDefinition` (109), `JobQueue` (18), `SchedulingPolicy` (8), `ServiceEnvironment` (6) |
| **Bedrock** | `ApplicationInferenceProfile` (2), `AutomatedReasoningPolicy` (3), `Blueprint` (3), `DataAutomationProject` (8), `DataSource` (12), `Flow` (14), `Guardrail` (19), `IntelligentPromptRouter` (5), `KnowledgeBase` (18), `Prompt` (4) |
| **BedrockAgentCore** | `ApiKeyCredentialProvider` (1), `BrowserCustom` (1), `CodeInterpreterCustom` (1), `ConfigurationBundle` (3), `Dataset` (3), `Evaluator` (4), `Gateway` (5), `GatewayRule` (3), `GatewayTarget` (9), `Harness` (2), `HarnessEndpoint` (2), `Memory` (6), `OAuth2CredentialProvider` (3), `OnlineEvaluationConfig` (3), `PaymentCredentialProvider` (1), `PaymentManager` (1), `Policy` (3), `ResourcePolicy` (1), `Runtime` (8), `RuntimeEndpoint` (1) |
| **CertificateManager** | `Certificate` (4) |
| **CloudFormation** | `GuardHook` (1), `Stack` (2), `StackSet` (6) |
| **CloudFront** | `AnycastIpList` (1), `CachePolicy` (7), `ContinuousDeploymentPolicy` (5), `Distribution` (55), `Function` (4), `KeyGroup` (1), `KeyValueStore` (2), `OriginRequestPolicy` (5), `PublicKey` (1), `RealtimeLogConfig` (3), `ResponseHeadersPolicy` (8), `VpcOrigin` (3) |
| **CloudTrail** | `EventDataStore` (1), `Trail` (19) |
| **CloudWatch** | `Alarm` (21), `AnomalyDetector` (6), `CompositeAlarm` (6), `Dashboard` (14), `InsightRule` (7), `MetricStream` (6) |
| **CodeBuild** | `Project` (37), `ReportGroup` (2), `SourceCredential` (4) |
| **CodeCommit** | `Repository` (11) |
| **CodeDeploy** | `Application` (7), `DeploymentConfig` (12), `DeploymentGroup` (23) |
| **CodePipeline** | `CustomActionType` (3), `Pipeline` (25), `Webhook` (2) |
| **Cognito** | `IdentityPool` (3), `IdentityPoolRoleAttachment` (7), `LogDeliveryConfiguration` (3), `ManagedLoginBranding` (2), `UserPool` (52), `UserPoolClient` (21), `UserPoolDomain` (7), `UserPoolGroup` (1), `UserPoolIdentityProvider` (11), `UserPoolResourceServer` (4), `UserPoolRiskConfigurationAttachment` (6), `UserPoolUICustomizationAttachment` (2) |
| **Config** | `ConfigRule` (6), `ConfigurationAggregator` (2), `ConfigurationRecorder` (7), `ConformancePack` (1), `RemediationConfiguration` (2) |
| **DocDB** | `DBCluster` (14), `DBInstance` (1), `DBSubnetGroup` (2), `EventSubscription` (1) |
| **DocDBElastic** | `Cluster` (7) |
| **DynamoDB** | `GlobalTable` (26), `Table` (28) |
| **EC2** | `ClientVpnAuthorizationRule` (1), `ClientVpnEndpoint` (6), `DHCPOptions` (2), `EIPAssociation` (1), `FlowLog` (4), `Instance` (10), `KeyPair` (1), `LaunchTemplate` (12), `NatGateway` (2), `NetworkAclEntry` (1), `NetworkInterface` (2), `PlacementGroup` (3), `PrefixList` (3), `Route` (1), `SecurityGroup` (7), `SecurityGroupEgress` (5), `SecurityGroupIngress` (5), `Subnet` (14), `TrafficMirrorTarget` (1), `TransitGateway` (2), `TransitGatewayRoute` (1), `Volume` (6), `VPC` (2), `VPCCidrBlock` (1), `VPCEndpoint` (4), `VPCGatewayAttachment` (1), `VPNConnection` (5) |
| **ECR** | `PullThroughCacheRule` (3), `RegistryScanningConfiguration` (1), `ReplicationConfiguration` (1), `Repository` (7), `RepositoryCreationTemplate` (8), `SigningConfiguration` (1) |
| **ECS** | `CapacityProvider` (3), `Cluster` (5), `Service` (37), `TaskDefinition` (64), `TaskSet` (2) |
| **EFS** | `AccessPoint` (1), `FileSystem` (7), `MountTarget` (4) |
| **EKS** | `AccessEntry` (14), `Addon` (5), `Cluster` (21), `FargateProfile` (5), `IdentityProviderConfig` (3), `Nodegroup` (21), `PodIdentityAssociation` (5) |
| **ElastiCache** | `CacheCluster` (9), `ReplicationGroup` (14), `User` (2), `UserGroup` (1) |
| **ElasticLoadBalancingV2** | `Listener` (57), `ListenerCertificate` (2), `ListenerRule` (37), `LoadBalancer` (37), `TargetGroup` (58), `TrustStore` (1), `TrustStoreRevocation` (1) |
| **Events** | `ApiDestination` (1), `Archive` (5), `Connection` (1), `Endpoint` (2), `EventBus` (2), `Rule` (23) |
| **EventSchemas** | `Discoverer` (1), `Registry` (1), `RegistryPolicy` (1), `Schema` (1) |
| **GlobalAccelerator** | `Accelerator` (1), `EndpointGroup` (5), `Listener` (2) |
| **Glue** | `Classifier` (6), `Connection` (5), `Crawler` (11), `CustomEntityType` (1), `Database` (1), `DataQualityRuleset` (1), `Job` (15), `MLTransform` (4), `Partition` (1), `Schema` (3), `SecurityConfiguration` (1), `Table` (1), `Trigger` (10), `UserDefinedFunction` (2), `Workflow` (1) |
| **Grafana** | `Workspace` (7) |
| **IAM** | `Group` (23), `GroupPolicy` (1), `InstanceProfile` (2), `ManagedPolicy` (31), `OIDCProvider` (2), `Policy` (29), `Role` (40), `RolePolicy` (1), `ServiceLinkedRole` (1), `User` (24), `UserPolicy` (1) |
| **IoT** | `Authorizer` (3), `Certificate` (1), `CertificateProvider` (1), `Command` (1), `DomainConfiguration` (3), `JobTemplate` (3), `MitigationAction` (1), `Policy` (4), `PolicyPrincipalAttachment` (1), `ProvisioningTemplate` (3), `RoleAlias` (1), `ScheduledAudit` (1), `Thing` (1), `ThingGroup` (2), `TopicRule` (5), `TopicRuleDestination` (2) |
| **Kinesis** | `ResourcePolicy` (4), `Stream` (5), `StreamConsumer` (2) |
| **KinesisAnalyticsV2** | `Application` (20), `ApplicationCloudWatchLoggingOption` (1), `ApplicationOutput` (1), `ApplicationReferenceDataSource` (1) |
| **KinesisFirehose** | `DeliveryStream` (68) |
| **KMS** | `Alias` (2), `Key` (12), `ReplicaKey` (4) |
| **Lambda** | `Alias` (7), `CodeSigningConfig` (1), `EventInvokeConfig` (5), `EventSourceMapping` (54), `Function` (46), `LayerVersion` (8), `LayerVersionPermission` (3), `Permission` (8), `Url` (8), `Version` (1) |
| **Logs** | `AccountPolicy` (6), `DeliveryDestination` (3), `Destination` (1), `LogAnomalyDetector` (2), `LogGroup` (10), `MetricFilter` (7), `QueryDefinition` (1), `ResourcePolicy` (1), `SubscriptionFilter` (6), `Transformer` (3) |
| **MemoryDB** | `Cluster` (8), `User` (1) |
| **MSK** | `BatchScramSecret` (2), `Cluster` (31), `ClusterPolicy` (1), `Configuration` (4), `Replicator` (10), `ServerlessCluster` (4) |
| **Neptune** | `DBCluster` (11), `DBClusterParameterGroup` (1), `DBInstance` (3), `DBSubnetGroup` (1), `GlobalCluster` (1) |
| **NeptuneGraph** | `Graph` (2), `PrivateGraphEndpoint` (1) |
| **NetworkFirewall** | `FirewallPolicy` (18), `RuleGroup` (34), `TLSInspectionConfiguration` (7) |
| **OpenSearchServerless** | `AccessPolicy` (7), `Collection` (2), `CollectionGroup` (3), `LifecyclePolicy` (4), `SecurityConfig` (5), `SecurityPolicy` (14) |
| **OpenSearchService** | `Domain` (65) |
| **Pipes** | `Pipe` (9) |
| **RDS** | `DBCluster` (19), `DBInstance` (33), `DBParameterGroup` (2), `DBProxy` (4), `DBProxyTargetGroup` (2), `DBShardGroup` (1), `DBSubnetGroup` (3), `EventSubscription` (3), `OptionGroup` (1) |
| **Redshift** | `Cluster` (20), `EventSubscription` (1), `ScheduledAction` (2) |
| **RedshiftServerless** | `Namespace` (5), `Workgroup` (6) |
| **Route53** | `CidrCollection` (11), `DNSSEC` (3), `HealthCheck` (30), `HostedZone` (14), `KeySigningKey` (9), `RecordSet` (75), `RecordSetGroup` (76) |
| **Route53Profiles** | `ProfileAssociation` (1), `ProfileResourceAssociation` (6) |
| **Route53Resolver** | `FirewallDomainList` (3), `FirewallRuleGroup` (18), `FirewallRuleGroupAssociation` (4), `ResolverDNSSECConfig` (1), `ResolverEndpoint` (18), `ResolverQueryLoggingConfig` (1), `ResolverQueryLoggingConfigAssociation` (1), `ResolverRule` (15), `ResolverRuleAssociation` (1) |
| **S3** | `AccessPoint` (1), `Bucket` (54), `BucketPolicy` (4), `StorageLens` (5), `StorageLensGroup` (3) |
| **S3Express** | `AccessPoint` (3), `DirectoryBucket` (11) |
| **Scheduler** | `Schedule` (10), `ScheduleGroup` (1) |
| **SecretsManager** | `RotationSchedule` (4), `Secret` (5), `SecretTargetAttachment` (1) |
| **ServiceDiscovery** | `HttpNamespace` (3), `Instance` (19), `PrivateDnsNamespace` (4), `PublicDnsNamespace` (4), `Service` (13) |
| **SES** | `ConfigurationSetEventDestination` (8), `ContactList` (1), `EmailIdentity` (6), `ReceiptRule` (6), `ReceiptRuleSet` (1), `Template` (1) |
| **SNS** | `Subscription` (9), `Topic` (12), `TopicPolicy` (1) |
| **SQS** | `Queue` (9), `QueuePolicy` (1) |
| **SSM** | `Association` (3), `Document` (3), `MaintenanceWindow` (2), `MaintenanceWindowTarget` (1), `MaintenanceWindowTask` (1), `Parameter` (5) |
| **StepFunctions** | `Activity` (3), `StateMachine` (26) |
| **Synthetics** | `Canary` (16) |
| **VerifiedPermissions** | `IdentitySource` (3), `Policy` (26), `PolicyStore` (23), `PolicyStoreAlias` (1), `PolicyTemplate` (29) |
| **WAFv2** | `IPSet` (3), `LoggingConfiguration` (3), `RegexPatternSet` (3), `RuleGroup` (18), `WebACL` (23), `WebACLAssociation` (2) |
| **XRay** | `Group` (1), `ResourcePolicy` (3), `SamplingRule` (6) |

</details>
<!-- supported-resources:end -->

Highlights:

- **ELBv2**: `idle_timeout` / `deregistration_delay` / `slow_start` attribute ranges (stringly-typed Key/Value attributes are invisible to schema validation)
- **IAM**: managed (6,144 chars) and inline (role/group/user) policy document size limits
- **CloudFront**: `MinTTL <= DefaultTTL <= MaxTTL` ordering, ACM certificates must live in `us-east-1`
- **Step Functions**: `Next`/`Default`/`Choices` must reference defined states (a dangling `StartAt` is already caught by the engine's built-in `E3601`)
- **EC2**: security group TCP/UDP port ranges and `FromPort <= ToPort`

## For AI agents

To add cdk-preflight to a CDK app:

1. `npm i -D cdk-preflight`
2. `npx cdk-preflight init` — or the shorter alias `npx cdkpf init` (finds the entry point via `cdk.json` and inserts `Preflight.apply(app)`; use `--dry-run` to preview)
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

## Scope and rule lifecycle

A constraint belongs in the pack when violating it makes a real deployment fail *and* no layer that sees the same synthesized template already blocks it. There is no further "is this worth a rule" question — if the gap is real, it gets a rule.

CDK L2 construct validation is deliberately **not** one of those layers. `CfnXxx` usage, escape hatches, `addPropertyOverride`, `cloudformation-include` and migrated templates all bypass L2, so an L2 guard covering the same mistake neither disqualifies a rule nor retires one.

That makes growth the normal state, and it has a consequence worth knowing before you upgrade: **new rules land in minor releases, so a minor upgrade can newly fail a `cdk synth` that passed yesterday.** That is intended, not a regression. If you need a frozen rule set, pin the version; to drop a single rule, `exclude: ['<rule-id>']`; to see everything without failing the build, `enforce: false`.

Rules move the other way too. Once the validation engine bundled in `aws-cdk-lib` (or CloudFormation's own pre-deploy validation) starts blocking a constraint, the rule is deleted rather than kept as a duplicate — staying on an older `aws-cdk-lib` and an older cdk-preflight keeps the old behavior.

## How it works

`Preflight.apply()` evaluates the rules with the [cloudformation-validate](https://github.com/aws-cloudformation/cloudformation-validate) Rust/WASM engine that ships inside `aws-cdk-lib` — no extra binaries, no network access at synth time. In the default enforce mode the engine is invoked through a dedicated CDK validation plugin so that violations fail synthesis; with `enforce: false` the rules are instead injected into the CDK built-in `CloudFormationValidatePlugin` and reported as warnings.

Constraints that *can* be expressed in schemas or generic engine rules also make good upstream PRs to that engine, but nothing here waits on one — the upstream release cycle is deliberately slower than this pack's. Each rule's `meta.yaml` tracks its upstream status so that retirement stays bookkeeping.

## Requirements

- `aws-cdk-lib` >= 2.267.0, released 2026-08-27 (the first release that bundles the built-in CloudFormation validator). This is a recent release — an existing CDK app may need an upgrade before cdk-preflight can run.

## Contributing

Rule authoring, the verification gates (including real-deploy reproduction), and the test layout are documented in [AGENTS.md](AGENTS.md) — written for AI coding agents and humans alike.

## License

Apache-2.0
