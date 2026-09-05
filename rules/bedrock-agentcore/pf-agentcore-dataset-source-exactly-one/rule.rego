package cdk_preflight

import rego.v1

# Source is documented as a union but the schema has no oneOf on it (measured
# 2026-09-05: {} and both members pass the engine); CreateDataset rejects both
# with "Exactly one of source.inlineExamples or source.s3Source must be provided".
violation contains make_diag_full("pf-agentcore-dataset-source-exactly-one", "ERROR", name,
	"Properties.Source",
	sprintf("Source holds %d members; CreateDataset fails with \"Exactly one of source.inlineExamples or source.s3Source must be provided\"", [n]),
	"Set exactly one of Source.InlineExamples or Source.S3Source",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateDataset.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Dataset")
	props := input.resources[name].properties
	is_object(props)
	src := object.get(props, "Source", null)
	is_object(src)
	n := count([1 | some k in ["InlineExamples", "S3Source"]; object.get(src, k, "__pf_absent") != "__pf_absent"])
	n != 1
}
