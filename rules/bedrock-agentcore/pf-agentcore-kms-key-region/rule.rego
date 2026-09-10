package cdk_preflight

import rego.v1

# A KmsKeyArn pointing at another region is rejected before the key is looked
# up ("Invalid arn <region>", measured 2026-09-10 on Dataset), so a template
# that works in one region silently breaks when deployed to another. The
# schema pattern only checks the ARN shape, and the engine has no way to know
# the deploy region; data.cdk_preflight.deploy_region is defined only in
# enforce mode with a concrete region, otherwise this rule skips.
_pf_ackms_types := ["AWS::BedrockAgentCore::Dataset", "AWS::BedrockAgentCore::Evaluator", "AWS::BedrockAgentCore::ConfigurationBundle"]

violation contains make_diag_full("pf-agentcore-kms-key-region", "ERROR", name,
	"Properties.KmsKeyArn",
	sprintf("The KMS key lives in '%s' but the stack deploys to '%s'; AgentCore rejects the ARN with \"Invalid arn %s\" before it looks the key up", [keyRegion, region, keyRegion]),
	"Reference a key in the deploy region (or drop KmsKeyArn to use the service-managed key)",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateDataset.html") if {
	some t in _pf_ackms_types
	some name in resources_of_type(t)
	region := data.cdk_preflight.deploy_region
	is_string(region)
	arn := resolve(name, "Properties.KmsKeyArn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "kms"
	keyRegion := parts[3]
	keyRegion != ""
	keyRegion != region
}
