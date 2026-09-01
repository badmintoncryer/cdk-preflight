# API Reference <a name="API Reference" id="api-reference"></a>


## Structs <a name="Structs" id="Structs"></a>

### PreflightOptions <a name="PreflightOptions" id="cdk-preflight.PreflightOptions"></a>

Options for {@link Preflight.apply}.

#### Initializer <a name="Initializer" id="cdk-preflight.PreflightOptions.Initializer"></a>

```typescript
import { PreflightOptions } from 'cdk-preflight'

const preflightOptions: PreflightOptions = { ... }
```

#### Properties <a name="Properties" id="Properties"></a>

| **Name** | **Type** | **Description** |
| --- | --- | --- |
| <code><a href="#cdk-preflight.PreflightOptions.property.enforce">enforce</a></code> | <code>boolean</code> | Fail synthesis when a bundled rule is violated. |
| <code><a href="#cdk-preflight.PreflightOptions.property.exclude">exclude</a></code> | <code>string[]</code> | Rule ids to disable (see `Preflight.ruleIds()` or docs/rules.md). |
| <code><a href="#cdk-preflight.PreflightOptions.property.includeUpstreamPending">includeUpstreamPending</a></code> | <code>boolean</code> | Include rules that are marked `pending-engine` (candidates that have been proposed to the upstream cloudformation-validate engine but are not merged yet). |
| <code><a href="#cdk-preflight.PreflightOptions.property.strict">strict</a></code> | <code>boolean</code> | In enforce mode, additionally fail synthesis on error-class findings (severity ERROR/FATAL) of the built-in validation engine itself, e.g. schema violations like `F3034`. This is the workaround for the CDK behavior where all built-in findings are downgraded to warnings. |

---

##### `enforce`<sup>Optional</sup> <a name="enforce" id="cdk-preflight.PreflightOptions.property.enforce"></a>

```typescript
public readonly enforce: boolean;
```

- *Type:* boolean
- *Default:* true

Fail synthesis when a bundled rule is violated.

In the default (enforce) mode, cdk-preflight evaluates its rules with its
own validation plugin and a violation makes `cdk synth` fail — the whole
point of preflight checks is that a template known to fail at deploy time
never leaves your machine. Set `enforce: false` to observe first: findings
are then reported through the CDK built-in CloudFormation validator and
surface as synth warnings with construct traces, which can be muted per
finding via `Acknowledge with 'CloudFormation-Validate::<rule-id>'`.

---

##### `exclude`<sup>Optional</sup> <a name="exclude" id="cdk-preflight.PreflightOptions.property.exclude"></a>

```typescript
public readonly exclude: string[];
```

- *Type:* string[]
- *Default:* all bundled rules are enabled

Rule ids to disable (see `Preflight.ruleIds()` or docs/rules.md).

---

##### `includeUpstreamPending`<sup>Optional</sup> <a name="includeUpstreamPending" id="cdk-preflight.PreflightOptions.property.includeUpstreamPending"></a>

```typescript
public readonly includeUpstreamPending: boolean;
```

- *Type:* boolean
- *Default:* true

Include rules that are marked `pending-engine` (candidates that have been proposed to the upstream cloudformation-validate engine but are not merged yet).

Disable this if you run a newer engine that already covers them.

---

##### `strict`<sup>Optional</sup> <a name="strict" id="cdk-preflight.PreflightOptions.property.strict"></a>

```typescript
public readonly strict: boolean;
```

- *Type:* boolean
- *Default:* false

In enforce mode, additionally fail synthesis on error-class findings (severity ERROR/FATAL) of the built-in validation engine itself, e.g. schema violations like `F3034`. This is the workaround for the CDK behavior where all built-in findings are downgraded to warnings.

Only effective in enforce mode (the default).

---

## Classes <a name="Classes" id="Classes"></a>

### Preflight <a name="Preflight" id="cdk-preflight.Preflight"></a>

cdk-preflight: catch deploy-time CloudFormation failures at synth time.

Injects a curated Rego rule pack (constraints that resource provider schemas
do not express: doc-only value limits, cross-property and cross-resource
rules) into the AWS CDK built-in CloudFormation validator.

*Example*

```typescript
declare const app: App;
Preflight.apply(app);
```



#### Static Functions <a name="Static Functions" id="Static Functions"></a>

| **Name** | **Description** |
| --- | --- |
| <code><a href="#cdk-preflight.Preflight.apply">apply</a></code> | Register the cdk-preflight rules on an App or Stage. |
| <code><a href="#cdk-preflight.Preflight.ruleIds">ruleIds</a></code> | The ids of all bundled rules. |

---

##### `apply` <a name="apply" id="cdk-preflight.Preflight.apply"></a>

```typescript
import { Preflight } from 'cdk-preflight'

Preflight.apply(scope: IConstruct, options?: PreflightOptions)
```

Register the cdk-preflight rules on an App or Stage.

###### `scope`<sup>Required</sup> <a name="scope" id="cdk-preflight.Preflight.apply.parameter.scope"></a>

- *Type:* constructs.IConstruct

---

###### `options`<sup>Optional</sup> <a name="options" id="cdk-preflight.Preflight.apply.parameter.options"></a>

- *Type:* <a href="#cdk-preflight.PreflightOptions">PreflightOptions</a>

---

##### `ruleIds` <a name="ruleIds" id="cdk-preflight.Preflight.ruleIds"></a>

```typescript
import { Preflight } from 'cdk-preflight'

Preflight.ruleIds()
```

The ids of all bundled rules.




