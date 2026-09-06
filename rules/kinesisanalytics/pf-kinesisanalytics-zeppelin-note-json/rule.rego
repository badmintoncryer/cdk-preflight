package cdk_preflight

import rego.v1

_pf_kinznj_note(txt) if {
	o := json.unmarshal(txt)
	is_object(o)
	_pf_kinlib_has(o, "id")
	_pf_kinlib_has(o, "name")
}

violation contains make_diag_full("pf-kinesisanalytics-zeppelin-note-json", "ERROR", name,
	"Properties.ApplicationConfiguration.ApplicationCodeConfiguration.CodeContent.TextContent",
	"the Studio notebook code is not a Zeppelin note object; CreateApplication fails with \"Zeppelin application code provided in TextContent must be a valid Zeppelin note JSON object containing 'id' and 'name' fields\"",
	"Pass an exported Zeppelin note JSON (an object with id and name), not raw SQL or Python",
	"https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_CodeContent.html") if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	_pf_kinlib_zeppelin(_pf_kinlib_runtime(name))
	txt := resolve(name, "Properties.ApplicationConfiguration.ApplicationCodeConfiguration.CodeContent.TextContent")
	_pf_kinlib_lit(txt)
	not _pf_kinznj_note(txt)
}
