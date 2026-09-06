package cdk_preflight

import rego.v1

# CreateGuardrail resolves policy ARNs only in its own Region; an ARN whose
# Region field differs fails with "The provided automated reasoning policy
# ARN is invalid for the service region" (measured 2026-09-06 with a real
# policy in us-west-2). Needs data.cdk_preflight.deploy_region.
violation contains make_diag_full("pf-bedrock-guardrail-automated-reasoning-policy-region", "ERROR", name,
	sprintf("Properties.AutomatedReasoningPolicyConfig.Policies[%d]", [it.index]),
	sprintf("The Automated Reasoning policy lives in '%s' but the guardrail deploys to '%s'; CreateGuardrail fails with \"The provided automated reasoning policy ARN is invalid for the service region\"", [r, region]),
	"Reference a policy created in the guardrail's own Region",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-automated-reasoning-policy.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	region := _pf_bedrocklib_region
	some it in flatten_list(name, "Properties.AutomatedReasoningPolicyConfig.Policies")
	r := _pf_bedrocklib_arn_region(it.value)
	r != region
}
