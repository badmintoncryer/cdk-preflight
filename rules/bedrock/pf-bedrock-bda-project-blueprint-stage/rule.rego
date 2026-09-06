package cdk_preflight

import rego.v1

# AWS::Bedrock::Blueprint creates the LIVE stage only (BlueprintStage is
# read-only on it), and a blueprint item may carry either a stage or a
# version, not both (measured 2026-09-06).
_pf_bbs_url := "https://docs.aws.amazon.com/bedrock/latest/APIReference/API_data-automation_BlueprintItem.html"

_pf_bbs_items(name) := bps if {
	bps := object.get(object.get(_pf_bedrocklib_props(name), "CustomOutputConfiguration", {}), "Blueprints", [])
	is_array(bps)
}

violation contains make_diag_full("pf-bedrock-bda-project-blueprint-stage", "ERROR", name,
	sprintf("Properties.CustomOutputConfiguration.Blueprints[%d].BlueprintStage", [i]),
	sprintf("Blueprint '%s' is created by this template and therefore only has a LIVE stage, but the project asks for DEVELOPMENT; CreateDataAutomationProject fails with \"Incorrect Blueprint Arn or Version provided in the custom configuration\"", [bp]),
	"Drop BlueprintStage (LIVE is the default) for blueprints managed by CloudFormation",
	_pf_bbs_url) if {
	some name in resources_of_type("AWS::Bedrock::DataAutomationProject")
	some i, b in _pf_bbs_items(name)
	is_object(b)
	b.BlueprintStage == "DEVELOPMENT"
	bp := _pf_bedrocklib_ref_target(object.get(b, "BlueprintArn", null), "AWS::Bedrock::Blueprint")
}

violation contains make_diag_full("pf-bedrock-bda-project-blueprint-stage", "ERROR", name,
	sprintf("Properties.CustomOutputConfiguration.Blueprints[%d].BlueprintVersion", [i]),
	"The blueprint item sets both BlueprintStage and BlueprintVersion; CreateDataAutomationProject fails with \"Incorrect Blueprint Arn or Version provided in the custom configuration\"",
	"Keep either BlueprintStage or BlueprintVersion",
	_pf_bbs_url) if {
	some name in resources_of_type("AWS::Bedrock::DataAutomationProject")
	some i, b in _pf_bbs_items(name)
	is_object(b)
	_pf_bedrocklib_has(b, "BlueprintStage")
	_pf_bedrocklib_has(b, "BlueprintVersion")
}
