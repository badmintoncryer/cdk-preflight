package cdk_preflight

import rego.v1

# Documented as a separate field; CreatePromptRouter requires it to be one of
# the Models entries (measured 2026-09-06). Literal ARNs only — intrinsics are
# marker objects and are skipped.
violation contains make_diag_full("pf-bedrock-prompt-router-fallback-model", "ERROR", name,
	"Properties.FallbackModel.ModelArn",
	sprintf("Fallback model '%s' is not in Models; CreatePromptRouter fails with \"The fallback model is not present in the list of models for routing\"", [fb]),
	"Use one of the Models entries as the FallbackModel",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_CreatePromptRouter.html") if {
	some name in resources_of_type("AWS::Bedrock::IntelligentPromptRouter")
	p := _pf_bedrocklib_props(name)
	fb := object.get(object.get(p, "FallbackModel", {}), "ModelArn", null)
	is_string(fb)
	ms := object.get(p, "Models", [])
	is_array(ms)
	count(ms) > 0
	arns := {m.ModelArn | some m in ms; is_object(m); is_string(m.ModelArn)}
	count(arns) == count(ms)
	not arns[fb]
}
