package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-instance-types-architecture", "ERROR", name,
	"Properties.ComputeResources.InstanceTypes",
	sprintf("InstanceTypes mixes the Graviton type %v with %v (\"arm-based instance type cannot be used with other instance types\")", [arm[0], x86[0]]),
	"Keep one architecture per compute environment",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_ComputeResource.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	ts := [v | some v in _pf_batch_ce_itypes(name); v != "optimal"]
	arm := [v | some v in ts; _pf_batch_arm(v)]
	x86 := [v | some v in ts; not _pf_batch_arm(v)]
	count(arm) > 0
	count(x86) > 0
}
