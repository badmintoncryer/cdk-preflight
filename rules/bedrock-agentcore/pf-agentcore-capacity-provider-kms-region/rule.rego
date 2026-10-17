package cdk_preflight

import rego.v1

# The KmsKeyId pattern accepts any region. CreateCapacityProvider rejects a
# key from another region before it looks the key up ("Invalid arn
# us-west-2"). Only Volumes[] is measured.
# data.cdk_preflight.deploy_region is defined only in enforce mode with a
# concrete region, otherwise this rule skips.
violation contains make_diag_full("pf-agentcore-capacity-provider-kms-region", "ERROR", name,
	sprintf("Properties.ComputeConfiguration.Ec2Configuration.Volumes.%d.EbsConfiguration.KmsKeyId", [v.i]),
	sprintf("The KMS key lives in '%s' but the stack deploys to '%s'; CreateCapacityProvider fails with \"Invalid arn %s\"", [r, region, r]),
	"Reference a key in the deploy region",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/runtime-instances-encryption.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::CapacityProvider")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	some v in _pf_accp_vols(name)
	arn := object.get(v.ebs, "KmsKeyId", null)
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[2] == "kms"
	r := parts[3]
	r != ""
	r != region
}
