package cdk_preflight

import rego.v1

# An Instances runtime takes its network from the capacity provider's
# VpcConfiguration. The schema allows both blocks; CreateAgentRuntime fails
# with "NetworkConfiguration is not allowed when capacityProviderConfiguration
# is specified".
violation contains make_diag_full("pf-agentcore-runtime-capacity-provider-network-config", "ERROR", name,
	"Properties.NetworkConfiguration",
	"CapacityProviderConfiguration is set, so NetworkConfiguration must be left out; CreateAgentRuntime fails with \"NetworkConfiguration is not allowed when capacityProviderConfiguration is specified\"",
	"Remove NetworkConfiguration; the capacity provider VpcConfiguration decides the network",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-instances.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Runtime")
	_pf_acrt_has_cp(name)
	_pf_ll_raw(name, "Properties.NetworkConfiguration") != "__pf_absent"
}
