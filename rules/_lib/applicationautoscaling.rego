package cdk_preflight

import rego.v1

# Shared helpers for the Application Auto Scaling rules. A ScalingPolicy names the
# scalable target it acts on in one of two shapes — ServiceNamespace /
# ScalableDimension / ResourceId written on the policy itself, or a Ref to a
# ScalableTarget in the same template through ScalingTargetId — and every rule
# that judges "which service is this scaling" has to read both. Loaded ahead of
# every rule (BUNDLED_LIBS); never emits diagnostics.

_pf_aaslib_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

# Absence can only be proven on the preprocessed document (resolve() is undefined
# both for a missing key and for an unresolvable token, see AGENTS.md).
_pf_aaslib_has(name, k) if {
	object.get(_pf_aaslib_props(name), k, "__pf_absent") != "__pf_absent"
}

# The 15 namespaces RegisterScalableTarget accepts. Doubles as the literal guard
# on a resolved ServiceNamespace: resolve() hands back a logical id for Ref and
# GetAtt, and no logical id is one of these.
_pf_aaslib_namespaces := {
	"appstream", "cassandra", "comprehend", "custom-resource", "dynamodb",
	"ec2", "ecs", "elasticache", "elasticmapreduce", "kafka", "lambda",
	"neptune", "rds", "sagemaker", "workspaces",
}

# The resource carrying the scalable target's identity for `name`: the resource
# itself when it spells the target out, else the ScalableTarget it Refs. The two
# are exclusive — the engine's schema already rejects a policy that has both.
_pf_aaslib_target_of(name) := name if _pf_aaslib_has(name, "ServiceNamespace")

_pf_aaslib_target_of(name) := t if {
	not _pf_aaslib_has(name, "ServiceNamespace")
	t := resolve(name, "Properties.ScalingTargetId")
	t in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
}

# ScalingTargetId may also be the literal "<id>|<dimension>|<namespace>" string a
# ScalableTarget returns at runtime; that form carries no logical id to follow, so
# both lookups stay undefined and the rule skips.
_pf_aaslib_namespace(name) := ns if {
	ns := resolve(_pf_aaslib_target_of(name), "Properties.ServiceNamespace")
	ns in _pf_aaslib_namespaces
}

# The same walk for ScalableDimension. Every one of the 24 values has three
# colon-separated segments, which is the literal guard: a logical id never does.
_pf_aaslib_dimension(name) := dim if {
	dim := resolve(_pf_aaslib_target_of(name), "Properties.ScalableDimension")
	is_string(dim)
	count(split(dim, ":")) == 3
}

# ---------------------------------------------- StepAdjustments (slice E)

# The step adjustments of a StepScaling policy. Absent and empty both come back
# as [] on purpose: the registry schema requires neither, so both reach the
# service and both draw "There must be at least one step adjustment".
_pf_aaslib_steps(name) := a if {
	cfg := object.get(_pf_aaslib_props(name), "StepScalingPolicyConfiguration", "__pf_absent")
	is_object(cfg)
	a := object.get(cfg, "StepAdjustments", [])
	is_array(a)
}

# A bound the template leaves out is minus/plus infinity, so both accessors stay
# undefined for it and every comparison below is written so that an undefined
# bound reads as unbounded on that side. `v != null` keeps an explicit JSON null
# out, since to_number(null) is 0 and would read as a real bound at zero.
_pf_aaslib_step_lo(adj) := to_number(v) if {
	v := object.get(adj, "MetricIntervalLowerBound", "__pf_absent")
	v != null
}

_pf_aaslib_step_hi(adj) := to_number(v) if {
	v := object.get(adj, "MetricIntervalUpperBound", "__pf_absent")
	v != null
}

# `a` ends at or before `b` starts. Undefined on an infinite end, which is right:
# an adjustment open at the top is below nothing.
_pf_aaslib_step_disjoint(a, b) if {
	_pf_aaslib_step_hi(a) <= _pf_aaslib_step_lo(b)
}

_pf_aaslib_step_ends_by(adj, x) if _pf_aaslib_step_hi(adj) <= x

_pf_aaslib_step_starts_after(adj, x) if _pf_aaslib_step_lo(adj) > x

_pf_aaslib_step_any_covers(adjs, x) if {
	some adj in adjs
	not _pf_aaslib_step_ends_by(adj, x)
	not _pf_aaslib_step_starts_after(adj, x)
}

_pf_aaslib_step_any_above(adjs, x) if {
	some adj in adjs
	_pf_aaslib_step_starts_after(adj, x)
}

_pf_aaslib_step_any_open(adjs, key) if {
	some adj in adjs
	object.get(adj, key, "__pf_absent") == "__pf_absent"
}

# Two adjustments both open on the same side. Doubles as the guard on the
# interval-algebra rules: two half-infinite intervals on one side always
# intersect, and the service reports that as the "at most one" error rather than
# as an overlap.
_pf_aaslib_step_two_open(name, key) if {
	adjs := _pf_aaslib_steps(name)
	some i, a in adjs
	some j, b in adjs
	i < j
	object.get(a, key, "__pf_absent") == "__pf_absent"
	object.get(b, key, "__pf_absent") == "__pf_absent"
}
