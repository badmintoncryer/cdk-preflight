package cdk_preflight

import rego.v1

# CreateSchema parses Content and, for OpenApi3, validates it against the
# OpenAPI 3.0 meta-schema. Measured 2026-09-07, schemas:CreateSchema,
# us-east-1: 'not json' gives "Content is not valid JSON", openapi "2.0"
# gives "'openapi' does not match pattern '^3\.0\.\d(-.+)?$'", and a
# $schema key gives "additionalProperties '$schema' not allowed" — the last
# is what pasting a JSON Schema into an OpenApi3 schema produces.
_pf_schcontent_url := "https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-schema-create.html"

_pf_schcontent_raw(name) := c if {
	c := resolve(name, "Properties.Content")
	is_string(c)
}

_pf_schcontent_openapi(name) := obj if {
	resolve(name, "Properties.Type") == "OpenApi3"
	raw := _pf_schcontent_raw(name)
	json.is_valid(raw)
	obj := json.unmarshal(raw)
	is_object(obj)
}

violation contains make_diag_full("pf-eventschemas-schema-content", "ERROR", name,
	"Properties.Content",
	"Content is not valid JSON; CreateSchema fails with \"Content is not valid JSON\"",
	"Serialise the schema document to JSON",
	_pf_schcontent_url) if {
	some name in resources_of_type("AWS::EventSchemas::Schema")
	raw := _pf_schcontent_raw(name)
	not json.is_valid(raw)
}

violation contains make_diag_full("pf-eventschemas-schema-content", "ERROR", name,
	"Properties.Content",
	sprintf("Type is OpenApi3 but the document declares openapi '%s'; CreateSchema fails with \"'openapi' does not match pattern '^3\\\\.0\\\\.\\\\d(-.+)?$'\"", [v]),
	"Declare a 3.0.x version, e.g. \"openapi\": \"3.0.0\"",
	_pf_schcontent_url) if {
	some name in resources_of_type("AWS::EventSchemas::Schema")
	obj := _pf_schcontent_openapi(name)
	v := object.get(obj, "openapi", null)
	is_string(v)
	not regex.match(`^3\.0\.[0-9](-.+)?$`, v)
}

violation contains make_diag_full("pf-eventschemas-schema-content", "ERROR", name,
	"Properties.Content",
	"An OpenApi3 document may not carry a $schema key; CreateSchema fails with \"additionalProperties '$schema' not allowed\"",
	"Drop $schema, or set Type to JSONSchemaDraft4",
	_pf_schcontent_url) if {
	some name in resources_of_type("AWS::EventSchemas::Schema")
	obj := _pf_schcontent_openapi(name)
	object.get(obj, "$schema", "__pf_absent") != "__pf_absent"
}
