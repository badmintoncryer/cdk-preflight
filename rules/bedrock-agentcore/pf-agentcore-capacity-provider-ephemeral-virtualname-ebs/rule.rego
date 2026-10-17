package cdk_preflight

import rego.v1

# Like an EC2 block device mapping, an EphemeralVolumes entry is either an
# instance-store volume (VirtualName) or an EBS volume (Ebs). The schema allows
# both; CreateCapacityProvider fails with "virtualName and ebs are mutually
# exclusive".
violation contains make_diag_full("pf-agentcore-capacity-provider-ephemeral-virtualname-ebs", "ERROR", name,
	sprintf("Properties.ComputeConfiguration.Ec2Configuration.LaunchTemplateSource.LaunchParameters.EphemeralVolumes.%d", [e.i]),
	"The mapping sets both VirtualName and Ebs; CreateCapacityProvider fails with \"virtualName and ebs are mutually exclusive\"",
	"Keep VirtualName for an instance-store volume or Ebs for an EBS volume, not both",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_LaunchParameters.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::CapacityProvider")
	some e in _pf_accp_ephemeral(name)
	object.get(e.v, "VirtualName", "__pf_absent") != "__pf_absent"
	object.get(e.v, "Ebs", "__pf_absent") != "__pf_absent"
}
