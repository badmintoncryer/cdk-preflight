package cdk_preflight

import rego.v1

# EFS and S3 Files are reached over the runtime's VPC. The schema does not
# tie the access point entries to NetworkMode; CreateAgentRuntime fails with
# "Filesystem configurations with EFS or S3 Files access points require VPC
# network mode" before it looks the access point up.
_pf_acbyo_kinds := {"EfsAccessPoint", "S3FilesAccessPoint"}

violation contains make_diag_full("pf-agentcore-runtime-byo-filesystem-vpc", "ERROR", name,
	sprintf("Properties.FilesystemConfigurations.%d.%s", [e.i, k]),
	sprintf("%s needs NetworkMode VPC but the runtime is %s; CreateAgentRuntime fails with \"Filesystem configurations with EFS or S3 Files access points require VPC network mode\"", [k, mode]),
	"Set NetworkConfiguration.NetworkMode to VPC with subnets that reach the file system",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-filesystem-configurations.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Runtime")
	mode := resolve(name, "Properties.NetworkConfiguration.NetworkMode")
	is_string(mode)
	mode != "VPC"
	some e in _pf_acrt_fs(name)
	some k in _pf_acbyo_kinds
	object.get(e.v, k, "__pf_absent") != "__pf_absent"
}
