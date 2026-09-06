package cdk_preflight

import rego.v1

# Required by CreateDataAutomationProject, optional in the schema (measured
# 2026-09-06). An empty object is accepted and gives default settings.
violation contains make_diag_full("pf-bedrock-bda-project-standard-output-required", "ERROR", name,
	"Properties.StandardOutputConfiguration",
	"StandardOutputConfiguration is missing; CreateDataAutomationProject fails with \"Value at 'standardOutputConfiguration' failed to satisfy constraint: Member must not be null\"",
	"Add StandardOutputConfiguration ({} keeps the default settings)",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_data-automation_CreateDataAutomationProject.html") if {
	some name in resources_of_type("AWS::Bedrock::DataAutomationProject")
	not _pf_bedrocklib_has(_pf_bedrocklib_props(name), "StandardOutputConfiguration")
}
