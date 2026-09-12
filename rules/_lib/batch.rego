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

# ---- EKS pod properties ----------------------------------------------------

_pf_batch_pod(name) := p if {
	p := _pf_batch_oget(_pf_batch_get(name, "EksProperties"), "PodProperties")
	is_object(p)
}

_pf_batch_meta(name) := m if {
	m := _pf_batch_oget(_pf_batch_pod(name), "Metadata")
	is_object(m)
}

# Containers and init containers, as flatten_list's {index, value} records.
_pf_batch_eks_containers(name) := cs if {
	cs := array.concat(
		flatten_list(name, "Properties.EksProperties.PodProperties.Containers"),
		flatten_list(name, "Properties.EksProperties.PodProperties.InitContainers"),
	)
}

_pf_batch_eks_res(c, side) := r if {
	r := _pf_batch_oget(_pf_batch_oget(c, "Resources"), side)
	is_object(r)
}

# One resource value written by the user; a Ref is left alone.
_pf_batch_eks_resval(c, side, k) := v if {
	v := _pf_batch_oget(_pf_batch_eks_res(c, side), k)
	_pf_batch_lit(v)
}

# Both sides at once, for the checks that do not care which one carries it.
_pf_batch_eks_vals(c, k) := vs if {
	vs := [v |
		some side in ["Limits", "Requests"]
		v := _pf_batch_eks_resval(c, side, k)
	]
}

_pf_batch_eks_numval(c, side, k) := n if {
	v := _pf_batch_eks_resval(c, side, k)
	regex.match(`^[0-9]+(\.[0-9]+)?$`, v)
	n := to_number(v)
}

_pf_batch_keyset(o) := {k | some k, _ in o}

_pf_batch_eks_reskeys(c) := ks if {
	r := _pf_batch_oget(c, "Resources")
	is_object(r)
	ks := _pf_batch_keyset(object.get(r, "Limits", {})) | _pf_batch_keyset(object.get(r, "Requests", {}))
}

# cpu is a whole number or a multiple of 0.25; milliCPU ("100m") is rejected.
_pf_batch_eks_cpu_bad(v) if {
	not regex.match(`^[0-9]+(\.[0-9]+)?$`, v)
}

_pf_batch_eks_cpu_bad(v) if {
	regex.match(`^[0-9]+(\.[0-9]+)?$`, v)
	q := to_number(v) * 4
	q != round(q)
}

# A unit suffix other than Mi. A bare number is left alone.
_pf_batch_eks_mem_bad(v) if {
	regex.match(`^[0-9]+(\.[0-9]+)?[A-Za-z]+$`, v)
	not endswith(v, "Mi")
}

_pf_batch_eks_mib(v) := n if {
	regex.match(`^[0-9]+(Mi)?$`, v)
	n := to_number(trim_suffix(v, "Mi"))
}

# Kubernetes reserved prefixes, plus the service's own.
_pf_batch_k8s_reserved(k) if {
	some p in ["kubernetes.io/", "k8s.io/", "batch.amazonaws.com/"]
	startswith(k, p)
}

# The name half of a label or annotation key ("prefix/name" or just "name").
_pf_batch_k8s_name_ok(k) if {
	parts := split(k, "/")
	regex.match(`^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,61}[a-zA-Z0-9])?$`, parts[count(parts) - 1])
}

# ---- multi-node ------------------------------------------------------------

_pf_batch_np(name) := np if {
	np := _pf_batch_get(name, "NodeProperties")
	is_object(np)
}

_pf_batch_ranges(name) := rs if {
	rs := flatten_list(name, "Properties.NodeProperties.NodeRangeProperties")
}

# Every TargetNodes expression the template spells out in a parsable form.
_pf_batch_target_nodes(name) := ts if {
	ts := [t |
		some r in _pf_batch_ranges(name)
		t := object.get(r.value, "TargetNodes", null)
		_pf_batch_lit(t)
		regex.match(`^[0-9]*(:[0-9]*)?$`, t)
	]
}

_pf_batch_bound(s, d) := d if {
	s == ""
}

_pf_batch_bound(s, _) := n if {
	s != ""
	n := to_number(s)
}

# The node indexes one TargetNodes expression covers: "n", "n:", ":m", "n:m".
_pf_batch_target(s, _) := ns if {
	parts := split(s, ":")
	count(parts) == 1
	ns := {to_number(parts[0])}
}

_pf_batch_target(s, num) := ns if {
	parts := split(s, ":")
	count(parts) == 2
	ns := {n | some n in numbers.range(_pf_batch_bound(parts[0], 0), _pf_batch_bound(parts[1], num - 1))}
}

_pf_batch_covered(name, num) := union({s |
	some t in _pf_batch_target_nodes(name)
	s := _pf_batch_target(t, num)
})

# The three payload shapes a node range may carry, at most one of them.
_pf_batch_range_payloads(r) := ks if {
	ks := [k |
		some k in ["Container", "EcsProperties", "EksProperties"]
		_pf_batch_ohas(r, k)
	]
}

# ---- compute environment ---------------------------------------------------

_pf_batch_cr(name) := cr if {
	cr := _pf_batch_get(name, "ComputeResources")
	is_object(cr)
}

_pf_batch_crget(name, k) := v if {
	v := _pf_batch_oget(_pf_batch_cr(name), k)
}

_pf_batch_crhas(name, k) if {
	_pf_batch_crget(name, k)
}

# A number the template spells out, or the documented default when the key is
# absent. A Ref leaves it undefined so nothing fires on an unresolvable value.
_pf_batch_crnum(name, k, _) := n if {
	n := _pf_batch_crget(name, k)
	is_number(n)
}

_pf_batch_crnum(name, k, d) := d if {
	not _pf_batch_crhas(name, k)
}

_pf_batch_crtype(name) := t if {
	t := _pf_batch_crget(name, "Type")
	_pf_batch_lit(t)
}

_pf_batch_ce_fargate(name) if {
	_pf_batch_crtype(name) in {"FARGATE", "FARGATE_SPOT"}
}

_pf_batch_ce_ec2(name) if {
	_pf_batch_crtype(name) in {"EC2", "SPOT"}
}

# The capacity family a job queue sees; UNMANAGED environments have none.
_pf_batch_ce_kind(name) := "Fargate" if {
	_pf_batch_ce_fargate(name)
}

_pf_batch_ce_kind(name) := "EC2" if {
	_pf_batch_ce_ec2(name)
}

_pf_batch_ce_eks(name) if {
	_pf_batch_has(name, "EksConfiguration")
}

_pf_batch_ce_subnets(name) := vs if {
	vs := flatten_list(name, "Properties.ComputeResources.Subnets")
}

_pf_batch_ce_sgs(name) := vs if {
	vs := flatten_list(name, "Properties.ComputeResources.SecurityGroupIds")
}

# Instance types the template spells out; "optimal" carries no architecture.
_pf_batch_ce_itypes(name) := vs if {
	vs := [e.value |
		some e in flatten_list(name, "Properties.ComputeResources.InstanceTypes")
		_pf_batch_lit(e.value)
	]
}

_pf_batch_lt(name) := lt if {
	lt := _pf_batch_crget(name, "LaunchTemplate")
	is_object(lt)
}

_pf_batch_lt_overrides(name) := os if {
	os := flatten_list(name, "Properties.ComputeResources.LaunchTemplate.Overrides")
}

_pf_batch_targets(o) := ts if {
	ts := [t | some t in object.get(o, "TargetInstanceTypes", []); _pf_batch_lit(t)]
}

_pf_batch_ec2cfgs(name) := cs if {
	cs := flatten_list(name, "Properties.ComputeResources.Ec2Configuration")
}

# The Batch service-linked role, by ARN path or by bare name.
_pf_batch_slr(v) if {
	contains(v, "aws-service-role/batch.amazonaws.com")
}

_pf_batch_slr(v) if {
	endswith(v, "AWSServiceRoleForBatch")
}

# Graviton families: a generation digit followed by "g" (c6g, im4gn, x2gd), plus a1.
_pf_batch_arm(v) if {
	regex.match(`^[a-z]+[0-9]+g[a-z]*$`, split(v, ".")[0])
}

_pf_batch_arm(v) if {
	split(v, ".")[0] == "a1"
}

# The ComputeResources.Type an allocation strategy is restricted to.
_pf_batch_alloc_type(s) := "SPOT" if {
	startswith(s, "SPOT_")
}

_pf_batch_alloc_type(s) := "EC2" if {
	s == "BEST_FIT_PROGRESSIVE_ORDERED"
}

# ImageType values Batch accepts, which differ between EKS and ECS environments.
_pf_batch_image_types(name) := {"EKS_AL2", "EKS_AL2_NVIDIA", "EKS_AL2023", "EKS_AL2023_NVIDIA"} if {
	_pf_batch_ce_eks(name)
}

_pf_batch_image_types(name) := {"ECS_AL2", "ECS_AL2_NVIDIA", "ECS_AL2023", "ECS_AL2023_NVIDIA"} if {
	not _pf_batch_ce_eks(name)
}

# Amazon Linux 2 images: EKS support ended 2025-11-26, ECS creation 2026-06-30.
_pf_batch_image_eol := {"ECS_AL2", "ECS_AL2_NVIDIA", "EKS_AL2", "EKS_AL2_NVIDIA"}

# BEST_FIT is the allocation strategy Batch applies when none is named; it is
# the one that needs a Spot fleet role.
_pf_batch_ce_bestfit(name) if {
	not _pf_batch_crhas(name, "AllocationStrategy")
}

_pf_batch_ce_bestfit(name) if {
	_pf_batch_crget(name, "AllocationStrategy") == "BEST_FIT"
}
