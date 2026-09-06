package cdk_preflight

import rego.v1

# Both lists lack minItems in the schema; the service requires at least one
# entry when the list is given (measured 2026-09-06).
_pf_bot_lists := {"Properties.StandardOutputConfiguration.Document.Extraction.Granularity.Types": "Document Granularity Type", "Properties.StandardOutputConfiguration.Document.OutputFormat.TextFormat.Types": "Document Text Output Format Type"}

_pf_bot_get(p, path) := v if {
	parts := split(path, ".")
	v := object.get(p, array.slice(parts, 1, count(parts)), null)
}

violation contains make_diag_full("pf-bedrock-bda-project-output-types", "ERROR", name,
	path,
	sprintf("The list is empty; CreateDataAutomationProject fails with \"At least 1 %s should be present\"", [what]),
	"List at least one type, or omit the block to keep the defaults",
	"https://docs.aws.amazon.com/bedrock/latest/APIReference/API_data-automation_DocumentStandardOutputConfiguration.html") if {
	some name in resources_of_type("AWS::Bedrock::DataAutomationProject")
	some path, what in _pf_bot_lists
	v := _pf_bot_get(_pf_bedrocklib_props(name), path)
	is_array(v)
	count(v) == 0
}
