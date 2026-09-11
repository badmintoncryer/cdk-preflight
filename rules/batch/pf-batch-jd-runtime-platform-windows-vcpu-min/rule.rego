package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-runtime-platform-windows-vcpu-min", "ERROR", name,
	"Properties.ContainerProperties.ResourceRequirements",
	sprintf("a Windows job definition asks for %v vCPU (\"vCPU must be at least 1 for Windows Job definition, got %v.\")", [n, n]),
	"Request at least 1 vCPU",
	"https://docs.aws.amazon.com/batch/latest/userguide/create-compute-environment-fargate.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	f := _pf_batch_oget(_pf_batch_cpget(name, "RuntimePlatform"), "OperatingSystemFamily")
	startswith(f, "WINDOWS_")
	v := _pf_batch_rr(_pf_batch_cp(name), "VCPU")
	_pf_batch_lit(v)
	n := to_number(v)
	n < 1
}
