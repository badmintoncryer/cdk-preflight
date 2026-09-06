package cdk_preflight

import rego.v1

# The STANDARD tier runs on cross-Region compute, so the guardrail must carry
# a CrossRegionConfig (measured 2026-09-06 for both the content-filter and the
# denied-topic tier).
_pf_gstc_tier(name) := ["Properties.ContentPolicyConfig.ContentFiltersTierConfig.TierName", "content filters"] if {
	resolve(name, "Properties.ContentPolicyConfig.ContentFiltersTierConfig.TierName") == "STANDARD"
}

_pf_gstc_tier(name) := ["Properties.TopicPolicyConfig.TopicsTierConfig.TierName", "denied topics"] if {
	resolve(name, "Properties.TopicPolicyConfig.TopicsTierConfig.TierName") == "STANDARD"
}

violation contains make_diag_full("pf-bedrock-guardrail-standard-tier-cross-region", "ERROR", name,
	t[0],
	sprintf("The %s use the STANDARD tier but the guardrail has no CrossRegionConfig; CreateGuardrail fails with \"Enable cross-Region inference for your guardrail to use Standard tier\"", [t[1]]),
	"Add CrossRegionConfig.GuardrailProfileArn (e.g. the us.guardrail.v1:0 profile of the deploy Region), or use the CLASSIC tier",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-tiers.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	t := _pf_gstc_tier(name)
	not _pf_bedrocklib_has(_pf_bedrocklib_props(name), "CrossRegionConfig")
}
