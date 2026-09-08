package cdk_preflight

import rego.v1

# Shared helpers for the ECS rules. Absence has to be proven against the raw
# document (resolve() cannot tell "absent" from "unresolvable"), containers and
# volumes are always walked through flatten_list, and every name comparison is
# limited to literals so a Ref-valued Name never produces a false positive.
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.

# A user-written literal, not a Ref/GetAtt that resolve() turned into a logical id.
_pf_ecs_lit(v) if {
	is_string(v)
	not input.resources[v]
}

_pf_ecs_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

# Absent-safe object access; undefined when the key is missing.
_pf_ecs_oget(o, k) := v if {
	is_object(o)
	v := object.get(o, k, "__pf_absent")
	v != "__pf_absent"
}

_pf_ecs_ohas(o, k) if {
	_pf_ecs_oget(o, k)
}

# Task-level property straight from the document (absence is provable here).
_pf_ecs_get(name, k) := v if {
	v := _pf_ecs_oget(_pf_ecs_props(name), k)
}

_pf_ecs_has(name, k) if {
	_pf_ecs_get(name, k)
}

# The task definition asks for the Fargate launch type.
_pf_ecs_fargate(name) if {
	rc := resolve(name, "Properties.RequiresCompatibilities")
	is_array(rc)
	"FARGATE" in rc
}

# Container definitions as {index, value} pairs.
_pf_ecs_containers(name) := cs if {
	cs := flatten_list(name, "Properties.ContainerDefinitions")
}

_pf_ecs_cget(c, k) := v if {
	v := _pf_ecs_oget(c.value, k)
}

_pf_ecs_cname(c) := n if {
	n := object.get(c.value, "Name", "<unnamed>")
}

# Literal container names declared in the task definition.
_pf_ecs_names(name) := {n |
	some c in _pf_ecs_containers(name)
	n := object.get(c.value, "Name", null)
	_pf_ecs_lit(n)
}

# Literal volume names declared in the task definition.
_pf_ecs_volnames(name) := {n |
	some v in flatten_list(name, "Properties.Volumes")
	n := object.get(v.value, "Name", null)
	_pf_ecs_lit(n)
}

# Every port mapping of the task definition, flattened across containers.
_pf_ecs_portmappings(name) := [pm |
	some c in _pf_ecs_containers(name)
	pms := _pf_ecs_cget(c, "PortMappings")
	is_array(pms)
	some pm in pms
	is_object(pm)
]

# The task definition a service or task set points at, when it is a Ref to a
# task definition in the same template (a literal ARN or family:revision cannot
# be inspected, so those rules simply do not fire).
_pf_ecs_reftd(name, key) := td if {
	td := resolve(name, key)
	input.resources[td].resourceType == "AWS::ECS::TaskDefinition"
}

# Outside an inclusive range; two clauses so a single rule body can express it.
_pf_ecs_outside(v, lo, _) if {
	v < lo
}

_pf_ecs_outside(v, _, hi) if {
	v > hi
}

_pf_ecs_num(v) := n if {
	n := to_number(v)
}

_pf_ecs_chas(c, k) if {
	_pf_ecs_cget(c, k)
}
