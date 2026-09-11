package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-runtime-platform-cpu-arch-value", "ERROR", name,
	"Properties.ContainerProperties.RuntimePlatform.CpuArchitecture",
	sprintf("CpuArchitecture %v is not a supported architecture", [a]),
	"Use X86_64 or ARM64",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RuntimePlatform.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	a := _pf_batch_oget(_pf_batch_cpget(name, "RuntimePlatform"), "CpuArchitecture")
	_pf_batch_lit(a)
	not a in {"X86_64", "ARM64"}
}
