package cdk_preflight

import rego.v1

# CapacityProviderVolume.VolumeName refers to a Volumes[] name on the
# capacity provider; CreateAgentRuntime fails with "Volume name 'nope' does
# not exist in the CapacityProvider". Checked only when the capacity provider
# is in the same template and all its volume names are literals.
violation contains make_diag_full("pf-agentcore-runtime-capacity-provider-volume-undefined", "ERROR", name,
	sprintf("Properties.FilesystemConfigurations.%d.CapacityProviderVolume.VolumeName", [e.i]),
	sprintf("Capacity provider '%s' defines no volume named '%s' (it has %v); CreateAgentRuntime fails with \"Volume name '%s' does not exist in the CapacityProvider\"", [cp, v, names, v]),
	"Use a name from the capacity provider's Volumes, or add that volume to it",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-filesystem-configurations.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Runtime")
	cp := _pf_acrt_cp(name)
	names := _pf_accp_vol_names(cp)
	some e in _pf_acrt_fs(name)
	v := object.get(object.get(e.v, "CapacityProviderVolume", {}), "VolumeName", null)
	is_string(v)
	not v in names
}
