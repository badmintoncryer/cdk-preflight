package cdk_preflight

import rego.v1

# Blueprints are looked up in the project's own Region (measured 2026-09-06
# with a real blueprint in us-west-2). Needs deploy_region.
violation contains make_diag_full("pf-bedrock-bda-project-blueprint-region", "ERROR", name,
	sprintf("Properties.CustomOutputConfiguration.Blueprints[%d].BlueprintArn", [it.index]),
	sprintf("The blueprint lives in '%s' but the project deploys to '%s'; CreateDataAutomationProject fails with \"Incorrect Blueprint Arn or Version provided in the custom configuration\"", [r, region]),
	"Reference a blueprint created in the project's own Region",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_data-automation_BlueprintItem.html") if {
	some name in resources_of_type("AWS::Bedrock::DataAutomationProject")
	region := _pf_bedrocklib_region
	some it in flatten_list(name, "Properties.CustomOutputConfiguration.Blueprints")
	r := _pf_bedrocklib_arn_region(it.value.BlueprintArn)
	r != region
}
