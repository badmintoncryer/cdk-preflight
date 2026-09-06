package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-bedrock-bda-project-transcript-configuration", "ERROR", name,
	"Properties.StandardOutputConfiguration.Audio.Extraction.Category.TypeConfiguration.Transcript",
	"Transcript settings are configured but TRANSCRIPT is not among Audio.Extraction.Category.Types; CreateDataAutomationProject fails with \"Type configuration requires TRANSCRIPT type to be selected in the extraction types\"",
	"Add TRANSCRIPT to Audio.Extraction.Category.Types or drop the transcript settings",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_data-automation_AudioExtractionCategoryTypeConfiguration.html") if {
	some name in resources_of_type("AWS::Bedrock::DataAutomationProject")
	cat := object.get(object.get(object.get(_pf_bedrocklib_props(name), "StandardOutputConfiguration", {}), "Audio", {}), "Extraction", {}).Category
	is_object(cat)
	_pf_bedrocklib_has(object.get(cat, "TypeConfiguration", {}), "Transcript")
	types := object.get(cat, "Types", [])
	is_array(types)
	not "TRANSCRIPT" in types
}
