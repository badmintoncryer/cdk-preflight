package cdk_preflight

import rego.v1

# The schema says Encrypted "Defaults to true", but CreateCapacityProvider
# rejects a KmsKeyId when Encrypted is not sent as true ("kmsKeyId may only be
# set when encrypted is true"). Only Volumes[] is measured.
violation contains make_diag_full("pf-agentcore-capacity-provider-kms-requires-encrypted", "ERROR", name,
	sprintf("Properties.ComputeConfiguration.Ec2Configuration.Volumes.%d.EbsConfiguration.Encrypted", [v.i]),
	"KmsKeyId is set but Encrypted is not true; CreateCapacityProvider fails with \"kmsKeyId may only be set when encrypted is true\"",
	"Set Encrypted: true next to KmsKeyId",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_EbsVolumeConfiguration.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::CapacityProvider")
	some v in _pf_accp_vols(name)
	object.get(v.ebs, "KmsKeyId", "__pf_absent") != "__pf_absent"
	object.get(v.ebs, "Encrypted", false) == false
}
