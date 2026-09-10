package cdk_preflight

import rego.v1

# CreateDataset compares names case-insensitively across the account, so two
# datasets in one template collide even when only their casing differs (409
# ConflictException, measured 2026-09-10). The engine's own duplicate check
# (E3019) only looks at primaryIdentifier, which here is the read-only
# DatasetArn, so it never sees DatasetName.
violation contains make_diag_full("pf-agentcore-dataset-name-unique", "ERROR", name,
	"Properties.DatasetName",
	sprintf("DatasetName '%s' is already used by resource '%s' (names are compared case-insensitively); CreateDataset fails with \"A dataset with this name already exists in your account\"", [dsName, other]),
	"Give each dataset a distinct name; a different casing of the same name is not distinct",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateDataset.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Dataset")
	dsName := resolve(name, "Properties.DatasetName")
	is_string(dsName)
	some other in resources_of_type("AWS::BedrockAgentCore::Dataset")
	other < name
	otherName := resolve(other, "Properties.DatasetName")
	is_string(otherName)
	lower(otherName) == lower(dsName)
}
