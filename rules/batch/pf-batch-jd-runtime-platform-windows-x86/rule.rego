package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-runtime-platform-windows-x86", "ERROR", name,
	"Properties.ContainerProperties.RuntimePlatform",
	sprintf("OperatingSystemFamily %v is paired with CpuArchitecture %v (\"Windows supported only by X86_64 cpuArchitecture\")", [f, a]),
	"Use CpuArchitecture: X86_64 for Windows containers",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RuntimePlatform.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	rp := _pf_batch_cpget(name, "RuntimePlatform")
	f := _pf_batch_oget(rp, "OperatingSystemFamily")
	startswith(f, "WINDOWS_")
	a := _pf_batch_oget(rp, "CpuArchitecture")
	_pf_batch_lit(a)
	a != "X86_64"
}
