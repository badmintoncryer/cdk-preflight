package cdk_preflight

import rego.v1

# Automated Reasoning checks run on cross-Region compute, so a guardrail that
# attaches policies must also carry CrossRegionConfig (measured 2026-09-06).
violation contains make_diag_full("pf-bedrock-guardrail-automated-reasoning-cross-region", "ERROR", name,
	"Properties.AutomatedReasoningPolicyConfig",
	"AutomatedReasoningPolicyConfig is set but the guardrail has no CrossRegionConfig; CreateGuardrail fails with \"To use Automated Reasoning checks, your guardrail must have a cross-Region inference profile\"",
	"Add CrossRegionConfig.GuardrailProfileArn (e.g. the us.guardrail.v1:0 profile of the deploy Region)",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-automated-reasoning-policy.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	p := _pf_bedrocklib_props(name)
	_pf_bedrocklib_has(p, "AutomatedReasoningPolicyConfig")
	not _pf_bedrocklib_has(p, "CrossRegionConfig")
}
