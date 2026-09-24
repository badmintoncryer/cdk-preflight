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
