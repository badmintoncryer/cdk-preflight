package cdk_preflight

import rego.v1

# Matched by prefix rather than an allow list: AWS keeps adding Windows Server
# families, and a stale list would turn into a false positive.
violation contains make_diag_full("pf-batch-jd-runtime-platform-os-family-value", "ERROR", name,
	"Properties.ContainerProperties.RuntimePlatform.OperatingSystemFamily",
	sprintf("OperatingSystemFamily %v is not supported (\"RuntimePlatform supports only one from [WINDOWS_SERVER_2019_CORE, WINDOWS_SERVER_2019_FULL, WINDOWS_SERVER_2022_CORE, WINDOWS_SERVER_2022_FULL, LINUX] operating systems, provided %v\")", [f, f]),
	"Use LINUX or one of the WINDOWS_SERVER_* families",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RuntimePlatform.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	f := _pf_batch_oget(_pf_batch_cpget(name, "RuntimePlatform"), "OperatingSystemFamily")
	_pf_batch_lit(f)
	f != "LINUX"
	not startswith(f, "WINDOWS_SERVER_")
}
