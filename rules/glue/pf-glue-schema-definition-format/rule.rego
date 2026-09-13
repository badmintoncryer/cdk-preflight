package cdk_preflight

import rego.v1

# Two rejections measured against CreateSchema: text that is not JSON at all
# (AVRO and JSON formats are both JSON documents), and an AVRO record with no
# name. PROTOBUF is not JSON and is never judged here.
_pf_glueschdef_json := {"AVRO", "JSON"}

_pf_glueschdef_def(name) := d if {
	d := _pf_gluelib_str(name, "Properties.SchemaDefinition")
}

violation contains make_diag_full("pf-glue-schema-definition-format", "ERROR", name,
	"Properties.SchemaDefinition",
	sprintf("The SchemaDefinition is not valid JSON, so it cannot parse as %s; CreateSchema fails with \"Schema definition of %s data format is invalid\"", [df, df]),
	"Write the schema definition as a JSON document matching DataFormat",
	"https://docs.aws.amazon.com/glue/latest/dg/schema-registry.html") if {
	some name in resources_of_type("AWS::Glue::Schema")
	df := _pf_gluelib_str(name, "Properties.DataFormat")
	df in _pf_glueschdef_json
	d := _pf_glueschdef_def(name)
	not json.is_valid(d)
}

violation contains make_diag_full("pf-glue-schema-definition-format", "ERROR", name,
	"Properties.SchemaDefinition",
	"The AVRO record schema has no name; CreateSchema fails with \"Schema definition of AVRO data format is invalid: No name in schema\"",
	"Give the AVRO record a name, e.g. {\"type\":\"record\",\"name\":\"r\",\"fields\":[]}",
	"https://docs.aws.amazon.com/glue/latest/dg/schema-registry.html") if {
	some name in resources_of_type("AWS::Glue::Schema")
	_pf_gluelib_str(name, "Properties.DataFormat") == "AVRO"
	d := _pf_glueschdef_def(name)
	json.is_valid(d)
	parsed := json.unmarshal(d)
	is_object(parsed)
	object.get(parsed, "type", "") == "record"
	object.get(parsed, "name", "__pf_absent") == "__pf_absent"
}
