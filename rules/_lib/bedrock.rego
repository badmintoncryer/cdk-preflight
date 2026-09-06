package cdk_preflight

import rego.v1

# Shared helpers for the Amazon Bedrock rules (Guardrail, Prompt, Flow,
# KnowledgeBase, DataSource, IntelligentPromptRouter, ApplicationInferenceProfile,
# Data Automation). Loaded ahead of every rule (BUNDLED_LIBS); never emits
# diagnostics.

# Raw (preprocessed) properties object of a resource — the sanctioned way to
# prove a key absent. Intrinsics inside are marker objects, never strings.
_pf_bedrocklib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_bedrocklib_has(obj, key) if {
	is_object(obj)
	object.get(obj, key, "__pf_absent") != "__pf_absent"
}

_pf_bedrocklib_region := r if {
	r := data.cdk_preflight.deploy_region
	is_string(r)
}

_pf_bedrocklib_account := a if {
	a := data.cdk_preflight.deploy_account
	is_string(a)
}

# Region / account fields of an ARN string; undefined for non-ARNs, empty
# fields and marker objects (is_string fails).
_pf_bedrocklib_arn_region(arn) := r if {
	is_string(arn)
	p := split(arn, ":")
	count(p) >= 6
	p[0] == "arn"
	r := p[3]
	r != ""
}

_pf_bedrocklib_arn_account(arn) := a if {
	is_string(arn)
	p := split(arn, ":")
	count(p) >= 6
	p[0] == "arn"
	a := p[4]
	a != ""
}

# Model / inference-profile identifier: the part after the last "/" of an
# ARN, or the bare id.
_pf_bedrocklib_model_id(v) := id if {
	is_string(v)
	contains(v, "/")
	parts := split(v, "/")
	id := parts[count(parts) - 1]
}

_pf_bedrocklib_model_id(v) := v if {
	is_string(v)
	not contains(v, "/")
}

# Geographic prefixes of cross-Region (system-defined) inference profiles.
# Source Regions of a geo profile never change (inference-profiles-support.html),
# so a prefix that does not match the deploy Region is a deploy-time
# "Inference profile not found". Unknown prefixes are not judged.
_pf_bedrocklib_geo_prefixes := {"us", "us-gov", "eu", "apac", "global"}

_pf_bedrocklib_geo(id) := g if {
	is_string(id)
	g := split(id, ".")[0]
	_pf_bedrocklib_geo_prefixes[g]
}

_pf_bedrocklib_geo_ok(g, r) if g == "global"

_pf_bedrocklib_geo_ok(g, r) if {
	g == "us"
	startswith(r, "us-")
	not startswith(r, "us-gov-")
}

_pf_bedrocklib_geo_ok(g, r) if {
	g == "us-gov"
	startswith(r, "us-gov-")
}

_pf_bedrocklib_geo_ok(g, r) if {
	g == "eu"
	startswith(r, "eu-")
}

_pf_bedrocklib_geo_ok(g, r) if {
	g == "eu"
	r == "il-central-1"
}

_pf_bedrocklib_geo_ok(g, r) if {
	g == "apac"
	startswith(r, "ap-")
}

_pf_bedrocklib_geo_ok(g, r) if {
	g == "apac"
	r == "me-central-1"
}

# True when a model / profile reference (bare id or ARN) cannot be served from
# the deploy Region: the ARN carries another Region, or the geo prefix of a
# cross-Region profile does not cover the Region.
_pf_bedrocklib_model_region_mismatch(v, region) if {
	r := _pf_bedrocklib_arn_region(v)
	r != region
}

_pf_bedrocklib_model_region_mismatch(v, region) if {
	g := _pf_bedrocklib_geo(_pf_bedrocklib_model_id(v))
	not _pf_bedrocklib_geo_ok(g, region)
}

# Provider of a model id ("anthropic" for anthropic.claude-…, also behind a
# geo prefix such as us.anthropic.…).
_pf_bedrocklib_model_provider(v) := p if {
	segs := split(_pf_bedrocklib_model_id(v), ".")
	count(segs) >= 3
	_pf_bedrocklib_geo_prefixes[segs[0]]
	p := segs[1]
}

_pf_bedrocklib_model_provider(v) := p if {
	segs := split(_pf_bedrocklib_model_id(v), ".")
	count(segs) >= 2
	not _pf_bedrocklib_geo_prefixes[segs[0]]
	p := segs[0]
}

# Logical id of an in-template resource of `type` that a property value
# points at: resolve() turns {"Ref": X} into "X"; raw marker objects carry
# __ref for both Ref and Fn::GetAtt.
_pf_bedrocklib_ref_target(v, type) := t if {
	is_string(v)
	v in resources_of_type(type)
	t := v
}

_pf_bedrocklib_ref_target(v, type) := t if {
	is_object(v)
	t := object.get(v, "__ref", null)
	is_string(t)
	t in resources_of_type(type)
}

# The KnowledgeBase logical id a DataSource points at (Ref / GetAtt in the
# same template); undefined for literal ids.
_pf_bedrocklib_ds_kb(name) := kb if {
	kb := _pf_bedrocklib_ref_target(resolve(name, "Properties.KnowledgeBaseId"), "AWS::Bedrock::KnowledgeBase")
}

_pf_bedrocklib_ds_kb(name) := kb if {
	not resolve(name, "Properties.KnowledgeBaseId")
	p := _pf_bedrocklib_props(name)
	kb := _pf_bedrocklib_ref_target(object.get(p, "KnowledgeBaseId", null), "AWS::Bedrock::KnowledgeBase")
}

# Embedding model id of a vector knowledge base (literal ARN or a Fn::Sub the
# engine could flatten); undefined otherwise.
_pf_bedrocklib_kb_embed_model(kb) := id if {
	id := _pf_bedrocklib_model_id(resolve(kb, "Properties.KnowledgeBaseConfiguration.VectorKnowledgeBaseConfiguration.EmbeddingModelArn"))
}

# Bucket expression of an S3 reference: a literal name, or the token text of a
# Fn::Sub ("${Bucket}") so two references to the same in-template bucket compare
# equal. Accepts "s3://bucket[/...]" and "arn:aws:s3:::bucket".
_pf_bedrocklib_bucket_text(v) := v if is_string(v)

_pf_bedrocklib_bucket_text(v) := t if {
	is_object(v)
	d := object.get(v, "__dynamic", null)
	is_string(d)
	startswith(d, "Sub:")
	t := substring(d, 4, -1)
}

_pf_bedrocklib_bucket_expr(v) := b if {
	t := _pf_bedrocklib_bucket_text(v)
	startswith(t, "s3://")
	b := split(substring(t, 5, -1), "/")[0]
	b != ""
}

_pf_bedrocklib_bucket_expr(v) := b if {
	t := _pf_bedrocklib_bucket_text(v)
	regex.match(`^arn:[^:]*:s3:::`, t)
	b := split(split(t, ":::")[1], "/")[0]
	b != ""
}

# Flow definition: the Definition object, or DefinitionString parsed as JSON
# (CloudFormation-cased keys, same as FlowDefinition). Undefined when the
# string is not JSON (pf-bedrock-flow-definition-string-json reports that) or
# carries unresolved intrinsics.
_pf_bedrocklib_flow_def(name) := d if {
	p := _pf_bedrocklib_props(name)
	d := object.get(p, "Definition", null)
	is_object(d)
}

_pf_bedrocklib_flow_def(name) := d if {
	p := _pf_bedrocklib_props(name)
	not _pf_bedrocklib_has(p, "Definition")
	s := resolve(name, "Properties.DefinitionString")
	is_string(s)
	json.is_valid(s)
	d := json.unmarshal(s)
	is_object(d)
}

_pf_bedrocklib_flow_prop(name) := "Properties.Definition" if {
	_pf_bedrocklib_has(_pf_bedrocklib_props(name), "Definition")
}

_pf_bedrocklib_flow_prop(name) := "Properties.DefinitionString" if {
	not _pf_bedrocklib_has(_pf_bedrocklib_props(name), "Definition")
}

_pf_bedrocklib_flow_nodes(name) := [n | some n in object.get(_pf_bedrocklib_flow_def(name), "Nodes", []); is_object(n)]

_pf_bedrocklib_flow_conns(name) := [c | some c in object.get(_pf_bedrocklib_flow_def(name), "Connections", []); is_object(c)]

_pf_bedrocklib_flow_node_names(name) := {n.Name | some n in _pf_bedrocklib_flow_nodes(name); is_string(n.Name)}

# Names of the outputs / inputs declared on a node.
_pf_bedrocklib_node_outputs(n) := {o.Name | some o in object.get(n, "Outputs", []); is_object(o); is_string(o.Name)}

_pf_bedrocklib_node_inputs(n) := {i.Name | some i in object.get(n, "Inputs", []); is_object(i); is_string(i.Name)}

# Condition names declared on a Condition node.
_pf_bedrocklib_node_conditions(n) := {c.Name | some c in object.get(object.get(object.get(n, "Configuration", {}), "Condition", {}), "Conditions", []); is_object(c); is_string(c.Name)}
