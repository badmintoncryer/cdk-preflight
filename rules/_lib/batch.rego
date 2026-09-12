package cdk_preflight

import rego.v1

# Shared helpers for the AWS Batch rules. Absence is proven against the raw
# document (resolve() cannot tell "absent" from "unresolvable"), lists are
# always walked through flatten_list, and the launch type is read from
# PlatformCapabilities — which the API defaults to EC2 when it is missing.
# Loaded ahead of every rule (BUNDLED_LIBS); never emits diagnostics.

# A user-written literal, not a Ref/GetAtt that resolve() turned into a logical id.
_pf_batch_lit(v) if {
	is_string(v)
	not input.resources[v]
}

_pf_batch_props(name) := p if {
	p := input.resources[name].properties
	is_object(p)
}

# Absent-safe object access; undefined when the key is missing.
_pf_batch_oget(o, k) := v if {
	is_object(o)
	v := object.get(o, k, "__pf_absent")
	v != "__pf_absent"
}

_pf_batch_ohas(o, k) if {
	_pf_batch_oget(o, k)
}

_pf_batch_get(name, k) := v if {
	v := _pf_batch_oget(_pf_batch_props(name), k)
}

_pf_batch_has(name, k) if {
	_pf_batch_get(name, k)
}

# The launch type the job definition asks for. RegisterJobDefinition defaults
# to EC2 when PlatformCapabilities is absent.
_pf_batch_caps(name) := {c |
	some pc in flatten_list(name, "Properties.PlatformCapabilities")
	c := pc.value
	is_string(c)
}

_pf_batch_fargate(name) if {
	"FARGATE" in _pf_batch_caps(name)
}

_pf_batch_mi(name) if {
	"MANAGED_INSTANCES" in _pf_batch_caps(name)
}

_pf_batch_ec2(name) if {
	count(_pf_batch_caps(name)) == 0
}

_pf_batch_ec2(name) if {
	"EC2" in _pf_batch_caps(name)
}

# ContainerProperties and the nested objects the rules reach for most often.
_pf_batch_cp(name) := cp if {
	cp := _pf_batch_get(name, "ContainerProperties")
	is_object(cp)
}

_pf_batch_cpget(name, k) := v if {
	v := _pf_batch_oget(_pf_batch_cp(name), k)
}

_pf_batch_cphas(name, k) if {
	_pf_batch_cpget(name, k)
}

_pf_batch_lp(name) := lp if {
	lp := _pf_batch_cpget(name, "LinuxParameters")
	is_object(lp)
}

_pf_batch_volumes(name) := vs if {
	vs := flatten_list(name, "Properties.ContainerProperties.Volumes")
}

# The EFS configuration of one volume entry.
_pf_batch_efs(v) := e if {
	e := _pf_batch_oget(v.value, "EfsVolumeConfiguration")
	is_object(e)
}

# Resource requirements of a container object, by type (VCPU / MEMORY / GPU).
# A duplicated type has to stay single-valued here, otherwise every rule that
# reads one blows up with "function produced multiple outputs".
_pf_batch_rrs(c, t) := [v |
	some e in object.get(c, "ResourceRequirements", [])
	is_object(e)
	object.get(e, "Type", "") == t
	v := object.get(e, "Value", null)
]

_pf_batch_rr(c, t) := v if {
	vs := _pf_batch_rrs(c, t)
	count(vs) > 0
	v := vs[0]
}

_pf_batch_num(v) := n if {
	n := to_number(v)
}

# Outside an inclusive range; two clauses so a single rule body can express it.
_pf_batch_outside(v, lo, _) if {
	v < lo
}

_pf_batch_outside(v, _, hi) if {
	v > hi
}

_pf_batch_anykey(o, keys) if {
	some k in keys
	_pf_batch_ohas(o, k)
}

# EcsProperties: task elements, and every container inside them.
_pf_batch_ecs_tasks(name) := ts if {
	ts := flatten_list(name, "Properties.EcsProperties.TaskProperties")
}

_pf_batch_ecs_containers(name) := [{"ti": t.index, "ci": i, "c": c} |
	some t in _pf_batch_ecs_tasks(name)
	some i, c in object.get(t.value, "Containers", [])
	is_object(c)
]

# Literal container names declared inside one ECS task element.
_pf_batch_ecs_names(t) := {n |
	some c in object.get(t.value, "Containers", [])
	is_object(c)
	n := object.get(c, "Name", null)
	_pf_batch_lit(n)
}

# ---- job queue -------------------------------------------------------------

# The orchestration type of a job queue. CreateJobQueue defaults to ECS when
# JobQueueType is absent; a Ref leaves it undefined so nothing fires on it.
_pf_batch_qtype(name) := t if {
	t := _pf_batch_get(name, "JobQueueType")
	is_string(t)
	not input.resources[t]
}

_pf_batch_qtype(name) := "ECS" if {
	not _pf_batch_has(name, "JobQueueType")
}

# ---- ARNs ------------------------------------------------------------------

_pf_batch_arn_region(v) := r if {
	_pf_batch_lit(v)
	startswith(v, "arn:")
	parts := split(v, ":")
	count(parts) > 5
	r := parts[3]
	r != ""
}

_pf_batch_arn_resource(v) := s if {
	_pf_batch_lit(v)
	parts := split(v, ":")
	count(parts) > 5
	s := parts[5]
}

# The ARN's own region, but only when it differs from the deployment region.
_pf_batch_region_mismatch(v) := r if {
	r := _pf_batch_arn_region(v)
	region := data.cdk_preflight.deploy_region
	is_string(region)
	r != region
}

# The logical id behind a reference to an in-template resource. flatten_list
# hands back whichever shape the engine chose (a resolved logical id, a
# {__ref} marker, or the raw {"Ref": ...}), so all three are accepted.
_pf_batch_ref(v) := v if {
	is_string(v)
	input.resources[v]
}

_pf_batch_ref(v) := r if {
	is_object(v)
	r := object.get(v, "__ref", "__pf_absent")
	is_string(r)
}

_pf_batch_ref(v) := r if {
	is_object(v)
	object.get(v, "__ref", "__pf_absent") == "__pf_absent"
	r := object.get(v, "Ref", "__pf_absent")
	is_string(r)
}
