package cdk_preflight

import rego.v1

# Shared helpers for the Kinesis Data Streams and Managed Service for Apache
# Flink rules: ARN segment access, traversal of the raw document (resolve()
# cannot prove a key absent) and the runtime-environment families that drive
# the Managed Flink configuration tables.
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.

# A user-written literal, not a Ref/GetAtt that resolve() turned into a logical id.
_pf_kinlib_lit(v) if {
	is_string(v)
	not input.resources[v]
}

# ARN segments of a literal ARN; undefined for intrinsics and non-ARN strings.
_pf_kinlib_arn(v) := parts if {
	_pf_kinlib_lit(v)
	parts := split(v, ":")
	count(parts) >= 6
	parts[0] == "arn"
}

# region / account of an ARN belonging to `service`; undefined otherwise.
_pf_kinlib_arn_region(v, service) := r if {
	parts := _pf_kinlib_arn(v)
	parts[2] == service
	r := parts[3]
	r != ""
}

_pf_kinlib_arn_account(v, service) := a if {
	parts := _pf_kinlib_arn(v)
	parts[2] == service
	a := parts[4]
	a != ""
}

# Raw properties of a resource. The preprocessed document is the only place
# where "the key is absent" can be told apart from "the value is a token".
_pf_kinlib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

_pf_kinlib_obj(o, k) := v if {
	is_object(o)
	v := object.get(o, k, null)
	is_object(v)
}

_pf_kinlib_has(o, k) if {
	is_object(o)
	object.get(o, k, "__pf_absent") != "__pf_absent"
}

_pf_kinlib_appcfg(name) := c if c := _pf_kinlib_obj(_pf_kinlib_props(name), "ApplicationConfiguration")

_pf_kinlib_flinkcfg(name) := c if c := _pf_kinlib_obj(_pf_kinlib_appcfg(name), "FlinkApplicationConfiguration")

_pf_kinlib_runtime(name) := rt if {
	rt := resolve(name, "Properties.RuntimeEnvironment")
	is_string(rt)
}

_pf_kinlib_flink(rt) if startswith(rt, "FLINK-")

_pf_kinlib_zeppelin(rt) if startswith(rt, "ZEPPELIN-FLINK-")

# [logical id, index, artifact] for every Studio custom artifact.
_pf_kinlib_artifacts contains [name, i, a] if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	z := _pf_kinlib_obj(_pf_kinlib_appcfg(name), "ZeppelinApplicationConfiguration")
	arts := object.get(z, "CustomArtifactsConfiguration", null)
	is_array(arts)
	some i, a in arts
	is_object(a)
}

# [logical id, index, statement] for every Kinesis resource-policy statement.
_pf_kinlib_statements contains [name, i, s] if {
	some name in resources_of_type("AWS::Kinesis::ResourcePolicy")
	pol := _pf_kinlib_obj(_pf_kinlib_props(name), "ResourcePolicy")
	sts := object.get(pol, "Statement", null)
	is_array(sts)
	some i, s in sts
	is_object(s)
}
