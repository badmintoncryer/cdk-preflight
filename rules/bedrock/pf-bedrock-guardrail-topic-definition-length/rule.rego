package cdk_preflight

import rego.v1

# The schema allows 1000 characters (the STANDARD tier limit); the default
# CLASSIC tier stops at 200 and CreateGuardrail rejects longer definitions
# (measured 2026-09-06: 201 chars fails, 200 deploys, 300 deploys once
# TopicsTierConfig.TierName is STANDARD).
_pf_gtdl_standard(name) if {
	resolve(name, "Properties.TopicPolicyConfig.TopicsTierConfig.TierName") == "STANDARD"
}

violation contains make_diag_full("pf-bedrock-guardrail-topic-definition-length", "ERROR", name,
	sprintf("Properties.TopicPolicyConfig.TopicsConfig[%d].Definition", [i]),
	sprintf("Topic definition is %d characters but the CLASSIC tier allows 200; CreateGuardrail fails with \"One or more of your guardrail topic definitions exceeds the maximum allowed length\"", [n]),
	"Shorten the definition to 200 characters, or set TopicPolicyConfig.TopicsTierConfig.TierName: STANDARD (needs CrossRegionConfig)",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails-denied-topics.html") if {
	some name in resources_of_type("AWS::Bedrock::Guardrail")
	not _pf_gtdl_standard(name)
	p := _pf_bedrocklib_props(name)
	ts := object.get(object.get(p, "TopicPolicyConfig", {}), "TopicsConfig", [])
	some i, t in ts
	is_object(t)
	d := t.Definition
	is_string(d)
	n := count(d)
	n > 200
}
