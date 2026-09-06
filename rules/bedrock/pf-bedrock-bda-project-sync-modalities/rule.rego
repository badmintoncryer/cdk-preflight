package cdk_preflight

import rego.v1

# The synchronous API only handles documents and images; the project creation
# refuses audio/video blocks on a SYNC project (measured 2026-09-06).
violation contains make_diag_full("pf-bedrock-bda-project-sync-modalities", "ERROR", name,
	sprintf("Properties.StandardOutputConfiguration.%s", [m]),
	sprintf("ProjectType SYNC configures %s standard output; CreateDataAutomationProject fails with \"Sync project does not support video/audio modality in Standard Output Configuration\"", [m]),
	"Remove the Audio / Video blocks, or use ProjectType ASYNC",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_data-automation_CreateDataAutomationProject.html") if {
	some name in resources_of_type("AWS::Bedrock::DataAutomationProject")
	resolve(name, "Properties.ProjectType") == "SYNC"
	std := object.get(_pf_bedrocklib_props(name), "StandardOutputConfiguration", {})
	some m in ["Audio", "Video"]
	_pf_bedrocklib_has(std, m)
}
