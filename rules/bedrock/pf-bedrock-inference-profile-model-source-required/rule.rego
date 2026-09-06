package cdk_preflight

import rego.v1

# ModelSource is createOnly but not required in the schema; CreateInferenceProfile
# requires it and the CloudFormation handler crashes on the missing value
# (measured 2026-09-06).
violation contains make_diag_full("pf-bedrock-inference-profile-model-source-required", "ERROR", name,
	"Properties.ModelSource",
	"ModelSource is missing; CreateInferenceProfile requires modelSource.copyFrom and the stack fails",
	"Set ModelSource.CopyFrom to the ARN of a foundation model or a system-defined inference profile",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_CreateInferenceProfile.html") if {
	some name in resources_of_type("AWS::Bedrock::ApplicationInferenceProfile")
	not _pf_bedrocklib_has(_pf_bedrocklib_props(name), "ModelSource")
}
