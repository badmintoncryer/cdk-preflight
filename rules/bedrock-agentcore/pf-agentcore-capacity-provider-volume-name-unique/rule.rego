package cdk_preflight

import rego.v1

# Runtimes mount a capacity provider volume by its name, and
# CreateCapacityProvider rejects a repeated name ("Volume name 'dup' is used
# more than once; volume names must be unique"). Names are compared as written.
violation contains make_diag_full("pf-agentcore-capacity-provider-volume-name-unique", "ERROR", name,
	sprintf("Properties.ComputeConfiguration.Ec2Configuration.Volumes.%d.EbsConfiguration.Name", [b.i]),
	sprintf("Volume name '%s' appears more than once; CreateCapacityProvider fails with \"Volume name '%s' is used more than once; volume names must be unique\"", [n, n]),
	"Give each volume its own Name",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateCapacityProvider.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::CapacityProvider")
	vols := _pf_accp_vols(name)
	some a in vols
	some b in vols
	a.i < b.i
	n := object.get(a.ebs, "Name", null)
	is_string(n)
	object.get(b.ebs, "Name", null) == n
}
