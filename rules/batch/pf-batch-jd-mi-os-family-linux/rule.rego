package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-mi-os-family-linux", "ERROR", name,
	"Properties.EcsProperties.TaskProperties",
	sprintf("RuntimePlatform asks for %v on MANAGED_INSTANCES (\"runtimePlatform for MANAGED_INSTANCES only supports LINUX operating system family.\")", [f]),
	"Use OperatingSystemFamily: LINUX",
	"https://docs.aws.amazon.com/batch/latest/userguide/ecs-managed-instances-job-definitions.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_mi(name)
	some t in _pf_batch_ecs_tasks(name)
	f := _pf_batch_oget(_pf_batch_oget(t.value, "RuntimePlatform"), "OperatingSystemFamily")
	_pf_batch_lit(f)
	f != "LINUX"
}
