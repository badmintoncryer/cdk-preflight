package cdk_preflight

import rego.v1

# The profile is account-scoped: an ARN with another account id is refused
# ("The provided resource ARN is from a different account" / CloudFormation
# "Access denied", measured 2026-09-06). Needs data.cdk_preflight.deploy_account.
violation contains make_diag_full("pf-bedrock-guardrail-profile-account", "ERROR", name,
	"Properties.CrossRegionConfig.GuardrailProfileArn",
	sprintf("The guardrail profile ARN names account '%s' but the stack deploys to account '%s'; CreateGuardrail fails with \"The provided resource ARN is from a different account\"", [a, account]),
	"Build the profile ARN with ${AWS::AccountId}",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-cross-region-support.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	account := _pf_bedrocklib_account
	arn := resolve(name, "Properties.CrossRegionConfig.GuardrailProfileArn")
	a := _pf_bedrocklib_arn_account(arn)
	a != account
}
