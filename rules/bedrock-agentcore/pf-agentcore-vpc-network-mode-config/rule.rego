package cdk_preflight

import rego.v1

# Four resource types carry a {NetworkMode, <vpc block>} pair whose members are
# independent in the schema. The control plane requires the block for VPC and
# rejects it for PUBLIC (Runtime also for SANDBOX: "not allowed for non-VPC
# mode"). Table: [type, path to the NetworkConfiguration object, block key].
_pf_vpcnm_table := [
	["AWS::BedrockAgentCore::Runtime", "Properties.NetworkConfiguration", "NetworkModeConfig"],
	["AWS::BedrockAgentCore::BrowserCustom", "Properties.NetworkConfiguration", "VpcConfig"],
	["AWS::BedrockAgentCore::CodeInterpreterCustom", "Properties.NetworkConfiguration", "VpcConfig"],
	["AWS::BedrockAgentCore::Harness", "Properties.Environment.AgentCoreRuntimeEnvironment.NetworkConfiguration", "NetworkModeConfig"],
]

_pf_vpcnm_url := "https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_BrowserNetworkConfiguration.html"

# The raw NetworkConfiguration object from the preprocessed document, so that
# a block whose values are unresolvable Refs still counts as present.
_pf_vpcnm_raw(name, path) := obj if {
	props := input.resources[name].properties
	is_object(props)
	keys := split(trim_prefix(path, "Properties."), ".")
	obj := _pf_vpcnm_walk(props, keys)
	is_object(obj)
}

# ponytail: Rego has no recursion; the deepest table path is 3 keys, so
# unroll to 3. Add a branch when a deeper path enters the table.
_pf_vpcnm_walk(o, keys) := o[keys[0]] if count(keys) == 1

_pf_vpcnm_walk(o, keys) := o[keys[0]][keys[1]] if count(keys) == 2

_pf_vpcnm_walk(o, keys) := o[keys[0]][keys[1]][keys[2]] if count(keys) == 3

violation contains make_diag_full("pf-agentcore-vpc-network-mode-config", "ERROR", name,
	sprintf("%s.%s", [path, key]),
	sprintf("NetworkMode is VPC but %s is missing; the create call fails with \"%s is required for VPC mode\"", [key, key]),
	sprintf("Add %s with the Subnets and SecurityGroups to attach, or set NetworkMode to PUBLIC", [key]),
	_pf_vpcnm_url) if {
	some [t, path, key] in _pf_vpcnm_table
	some name in resources_of_type(t)
	resolve(name, sprintf("%s.NetworkMode", [path])) == "VPC"
	nc := _pf_vpcnm_raw(name, path)
	object.get(nc, key, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-agentcore-vpc-network-mode-config", "ERROR", name,
	sprintf("%s.%s", [path, key]),
	sprintf("NetworkMode is %s but %s is set; the create call fails with \"%s is not allowed for %s mode\"", [mode, key, key, mode]),
	sprintf("Remove %s, or set NetworkMode to VPC", [key]),
	_pf_vpcnm_url) if {
	some [t, path, key] in _pf_vpcnm_table
	some name in resources_of_type(t)
	mode := resolve(name, sprintf("%s.NetworkMode", [path]))
	is_string(mode)
	mode != "VPC"
	nc := _pf_vpcnm_raw(name, path)
	object.get(nc, key, "__pf_absent") != "__pf_absent"
}
