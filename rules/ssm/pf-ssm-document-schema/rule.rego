package cdk_preflight

import rego.v1

_pf_ssmds_url := "https://docs.aws.amazon.com/systems-manager/latest/userguide/documents-schemas-features.html"

_pf_ssmds_fix := "Use schemaVersion 2.2 with DocumentType Command, 0.3 with Automation, 1.0 with Session, 2.0/2.2 with Policy; set DocumentFormat TEXT only for ChangeCalendar; add Requires to ApplicationConfiguration documents"

# Content is a JSON object, or a string holding JSON (YAML strings are skipped)
_pf_ssmds_content(name) := c if {
	c := object.get(input.resources[name].properties, "Content", null)
	is_object(c)
}

_pf_ssmds_content(name) := c if {
	raw := object.get(input.resources[name].properties, "Content", null)
	is_string(raw)
	json.is_valid(raw)
	c := json.unmarshal(raw)
	is_object(c)
}

_pf_ssmds_type(name) := t if {
	t := resolve(name, "Properties.DocumentType")
	is_string(t)
}

_pf_ssmds_type(name) := "Command" if {
	object.get(input.resources[name].properties, "DocumentType", "__pf_absent") == "__pf_absent"
}

_pf_ssmds_schema(name) := sprintf("%v", [v]) if {
	v := object.get(_pf_ssmds_content(name), "schemaVersion", null)
	v != null
}

_pf_ssmds_allowed := {
	"Command": ["1.0", "1.2", "2.0", "2.2"],
	"Automation": ["0.3"],
	"Automation.ChangeTemplate": ["0.3"],
	"Session": ["1.0"],
	"Policy": ["2.0", "2.2"],
}

violation contains make_diag_full("pf-ssm-document-schema", "ERROR", name,
	"Properties.Content.schemaVersion",
	"schemaVersion 2.2 needs an explicit DocumentType; CreateDocument fails with \"Document type is required for schema version 2.2\"",
	_pf_ssmds_fix, _pf_ssmds_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	object.get(input.resources[name].properties, "DocumentType", "__pf_absent") == "__pf_absent"
	_pf_ssmds_schema(name) == "2.2"
}

violation contains make_diag_full("pf-ssm-document-schema", "ERROR", name,
	"Properties.Content.schemaVersion",
	sprintf("schemaVersion %s is not valid for a %s document (allowed: %s); CreateDocument fails with \"%s is not a valid schema version for %s document type\"", [sv, t, concat("/", _pf_ssmds_allowed[t]), sv, t]),
	_pf_ssmds_fix, _pf_ssmds_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	t := _pf_ssmds_type(name)
	sv := _pf_ssmds_schema(name)
	not _pf_ssmds_absent22(name, sv)
	_pf_ssmds_allowed[t]
	not sv in _pf_ssmds_allowed[t]
}

_pf_ssmds_absent22(name, sv) if {
	sv == "2.2"
	object.get(input.resources[name].properties, "DocumentType", "__pf_absent") == "__pf_absent"
}

_pf_ssmds_format(name) := f if {
	f := resolve(name, "Properties.DocumentFormat")
	is_string(f)
}

_pf_ssmds_format(name) := "JSON" if {
	object.get(input.resources[name].properties, "DocumentFormat", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-ssm-document-schema", "ERROR", name,
	"Properties.DocumentFormat",
	sprintf("ChangeCalendar documents must use DocumentFormat TEXT (iCalendar), not %s; CreateDocument fails with \"Document format '%s' is not supported.\"", [f, f]),
	_pf_ssmds_fix, _pf_ssmds_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	_pf_ssmds_type(name) == "ChangeCalendar"
	f := _pf_ssmds_format(name)
	f != "TEXT"
}

violation contains make_diag_full("pf-ssm-document-schema", "ERROR", name,
	"Properties.DocumentFormat",
	sprintf("DocumentFormat TEXT is only valid for ChangeCalendar documents, not %s; CreateDocument fails with \"Invalid document format: TEXT\"", [t]),
	_pf_ssmds_fix, _pf_ssmds_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	t := _pf_ssmds_type(name)
	t != "ChangeCalendar"
	_pf_ssmds_format(name) == "TEXT"
}

violation contains make_diag_full("pf-ssm-document-schema", "ERROR", name,
	"Properties.Requires",
	"ApplicationConfiguration documents must list their ApplicationConfigurationSchema document in Requires; CreateDocument fails with \"DocumentRequires cannot be empty when creating a document of type ApplicationConfiguration\"",
	_pf_ssmds_fix, _pf_ssmds_url) if {
	some name in resources_of_type("AWS::SSM::Document")
	_pf_ssmds_type(name) == "ApplicationConfiguration"
	count(flatten_list(name, "Properties.Requires")) == 0
}
