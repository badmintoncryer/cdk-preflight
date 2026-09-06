package cdk_preflight

import rego.v1

# Model ARNs are resolved in the router's own Region: another Region field
# ("Unsupported model type") or a cross-Region profile of another geography
# ("Inference profile … not Found or invalid") fails CreatePromptRouter
# (measured 2026-09-06). Needs data.cdk_preflight.deploy_region.
_pf_rmr_url := "https://docs.aws.amazon.com/bedrock/latest/userguide/prompt-routing.html"

violation contains make_diag_full("pf-bedrock-prompt-router-model-region", "ERROR", name,
	sprintf("Properties.Models[%d].ModelArn", [it.index]),
	sprintf("Model '%s' cannot be served from Region '%s'; CreatePromptRouter fails with \"Unsupported model type\" / \"Inference profile … not Found or invalid\"", [_pf_bedrocklib_model_id(arn), region]),
	"Reference the model (or a cross-Region profile of the deploy Region's geography) in the deploy Region",
	_pf_rmr_url) if {
	some name in resources_of_type("AWS::Bedrock::IntelligentPromptRouter")
	region := _pf_bedrocklib_region
	some it in flatten_list(name, "Properties.Models")
	arn := it.value.ModelArn
	_pf_bedrocklib_model_region_mismatch(arn, region)
}

violation contains make_diag_full("pf-bedrock-prompt-router-model-region", "ERROR", name,
	"Properties.FallbackModel.ModelArn",
	sprintf("Fallback model '%s' cannot be served from Region '%s'; CreatePromptRouter fails with \"Unsupported model type\" / \"Inference profile … not Found or invalid\"", [_pf_bedrocklib_model_id(arn), region]),
	"Reference the model (or a cross-Region profile of the deploy Region's geography) in the deploy Region",
	_pf_rmr_url) if {
	some name in resources_of_type("AWS::Bedrock::IntelligentPromptRouter")
	region := _pf_bedrocklib_region
	arn := resolve(name, "Properties.FallbackModel.ModelArn")
	_pf_bedrocklib_model_region_mismatch(arn, region)
}
