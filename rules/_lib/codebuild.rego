package cdk_preflight

import rego.v1

# Shared helpers for the CodeBuild rules. The raw (preprocessed) document is the
# only place where "the key is absent" can be told apart from "the value is a
# token", and most of these rules turn on absence, so every accessor here reads
# input.resources[...].properties rather than resolve().
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.

# A user-written literal, not a Ref/GetAtt that resolve() turned into a logical id.
_pf_codebuildlib_lit(v) if {
	is_string(v)
	not input.resources[v]
}

_pf_codebuildlib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_codebuildlib_obj(o, k) := v if {
	is_object(o)
	v := object.get(o, k, null)
	is_object(v)
}

_pf_codebuildlib_has(o, k) if {
	is_object(o)
	object.get(o, k, "__pf_absent") != "__pf_absent"
}

# A literal string member of a block; undefined for tokens and non-strings.
_pf_codebuildlib_str(o, k) := v if {
	is_object(o)
	v := object.get(o, k, null)
	_pf_codebuildlib_lit(v)
}

# CloudFormation accepts both the JSON boolean and the string, and templates
# synthesized from YAML carry either, so "== true" alone misses half the cases.
_pf_codebuildlib_true(v) if v == true

_pf_codebuildlib_true(v) if {
	is_string(v)
	lower(v) == "true"
}

# to_number(null) is 0 in the engine's Rego build, so the value has to be
# narrowed to a number or a numeric string first.
_pf_codebuildlib_num(v) := v if is_number(v)

_pf_codebuildlib_num(v) := n if {
	is_string(v)
	n := to_number(v)
}

# ---- the four blocks every CodeBuild rule reads -----------------------------

_pf_codebuildlib_env(name) := e if e := _pf_codebuildlib_obj(_pf_codebuildlib_props(name), "Environment")

_pf_codebuildlib_source(name) := s if s := _pf_codebuildlib_obj(_pf_codebuildlib_props(name), "Source")

_pf_codebuildlib_artifacts(name) := a if a := _pf_codebuildlib_obj(_pf_codebuildlib_props(name), "Artifacts")

_pf_codebuildlib_cache(name) := c if c := _pf_codebuildlib_obj(_pf_codebuildlib_props(name), "Cache")

_pf_codebuildlib_batch(name) := b if b := _pf_codebuildlib_obj(_pf_codebuildlib_props(name), "BuildBatchConfig")

_pf_codebuildlib_env_type(name) := t if t := _pf_codebuildlib_str(_pf_codebuildlib_env(name), "Type")

_pf_codebuildlib_compute_type(name) := t if t := _pf_codebuildlib_str(_pf_codebuildlib_env(name), "ComputeType")

_pf_codebuildlib_source_type(name) := t if t := _pf_codebuildlib_str(_pf_codebuildlib_source(name), "Type")

_pf_codebuildlib_artifacts_type(name) := t if t := _pf_codebuildlib_str(_pf_codebuildlib_artifacts(name), "Type")

_pf_codebuildlib_cache_type(name) := t if t := _pf_codebuildlib_str(_pf_codebuildlib_cache(name), "Type")

# ---- ARNs ------------------------------------------------------------------

_pf_codebuildlib_arn_part(v, i) := p if {
	_pf_codebuildlib_lit(v)
	startswith(v, "arn:")
	parts := split(v, ":")
	count(parts) > 5
	p := parts[i]
	p != ""
}

_pf_codebuildlib_arn_service(v) := s if s := _pf_codebuildlib_arn_part(v, 2)

_pf_codebuildlib_arn_region(v) := r if r := _pf_codebuildlib_arn_part(v, 3)

# The ARN's own region, but only when it differs from the deployment region.
_pf_codebuildlib_region_mismatch(v) := r if {
	r := _pf_codebuildlib_arn_region(v)
	region := data.cdk_preflight.deploy_region
	is_string(region)
	r != region
}
