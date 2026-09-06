package cdk_preflight

import rego.v1

# The profile ARN is arn:…:bedrock:<source-region>:<account>:guardrail-profile/<id>;
# CreateGuardrail rejects any other Region field ("The provided ARN is invalid
# for the service region", measured 2026-09-06). Needs deploy_region.
violation contains make_diag_full("pf-bedrock-guardrail-profile-region", "ERROR", name,
	"Properties.CrossRegionConfig.GuardrailProfileArn",
	sprintf("The guardrail profile ARN names Region '%s' but the guardrail deploys to '%s'; CreateGuardrail fails with \"The provided ARN is invalid for the service region\"", [r, region]),
	"Build the profile ARN with ${AWS::Region} (arn:${AWS::Partition}:bedrock:${AWS::Region}:${AWS::AccountId}:guardrail-profile/<id>)",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-cross-region-support.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	region := _pf_bedrocklib_region
	arn := resolve(name, "Properties.CrossRegionConfig.GuardrailProfileArn")
	r := _pf_bedrocklib_arn_region(arn)
	r != region
}
