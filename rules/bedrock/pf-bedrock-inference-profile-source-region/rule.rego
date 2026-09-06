package cdk_preflight

import rego.v1

# CreateInferenceProfile looks the source up in its own Region only: another
# Region field ("Model not found") or a cross-Region profile of another
# geography ("Inference profile not found") fails (measured 2026-09-06 with
# models that exist in the other Region). Needs deploy_region.
violation contains make_diag_full("pf-bedrock-inference-profile-source-region", "ERROR", name,
	"Properties.ModelSource.CopyFrom",
	sprintf("Source '%s' cannot be served from Region '%s'; CreateInferenceProfile fails with \"Model not found\" / \"Inference profile not found\"", [_pf_bedrocklib_model_id(arn), region]),
	"Copy from the model ARN of the deploy Region (arn:${AWS::Partition}:bedrock:${AWS::Region}::foundation-model/<id>) or from a profile of its geography",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_CreateInferenceProfile.html") if {
	some name in resources_of_type("AWS::Bedrock::ApplicationInferenceProfile")
	region := _pf_bedrocklib_region
	arn := resolve(name, "Properties.ModelSource.CopyFrom")
	_pf_bedrocklib_model_region_mismatch(arn, region)
}
