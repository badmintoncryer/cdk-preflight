package cdk_preflight

import rego.v1

# FilesystemConfigurations entries are a union and the schema allows every
# kind on every runtime. CreateAgentRuntime ties them to the compute type:
# CapacityProviderVolume only with CapacityProviderConfiguration
# ("capacityProviderVolume configurations require
# capacityProviderConfiguration to be specified"), SessionStorage /
# EfsAccessPoint / S3FilesAccessPoint only without it ("sessionStorage, EFS,
# and S3 Files storage types are not supported with
# capacityProviderConfiguration").
_pf_acfsc_microvm := {"SessionStorage", "EfsAccessPoint", "S3FilesAccessPoint"}

violation contains make_diag_full("pf-agentcore-runtime-filesystem-compute-type", "ERROR", name,
	sprintf("Properties.FilesystemConfigurations.%d.CapacityProviderVolume", [e.i]),
	"CapacityProviderVolume needs CapacityProviderConfiguration; CreateAgentRuntime fails with \"capacityProviderVolume configurations require capacityProviderConfiguration to be specified\"",
	"Add CapacityProviderConfiguration, or use SessionStorage on a runtime without a capacity provider",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-filesystem-configurations.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Runtime")
	not _pf_acrt_has_cp(name)
	some e in _pf_acrt_fs(name)
	object.get(e.v, "CapacityProviderVolume", "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-agentcore-runtime-filesystem-compute-type", "ERROR", name,
	sprintf("Properties.FilesystemConfigurations.%d.%s", [e.i, k]),
	sprintf("%s is not available on a capacity provider runtime; CreateAgentRuntime fails with \"sessionStorage, EFS, and S3 Files storage types are not supported with capacityProviderConfiguration\"", [k]),
	"Use a CapacityProviderVolume, or drop CapacityProviderConfiguration",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-filesystem-configurations.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Runtime")
	_pf_acrt_has_cp(name)
	some e in _pf_acrt_fs(name)
	some k in _pf_acfsc_microvm
	object.get(e.v, k, "__pf_absent") != "__pf_absent"
}
