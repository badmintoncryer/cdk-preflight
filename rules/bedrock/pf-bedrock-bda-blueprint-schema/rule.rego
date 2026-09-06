package cdk_preflight

import rego.v1

# The schema type is a free object; CreateBlueprint requires the blueprint
# JSON-schema envelope: class, description and a properties map (measured
# 2026-09-06).
violation contains make_diag_full("pf-bedrock-bda-blueprint-schema", "ERROR", name,
	sprintf("Properties.Schema.%s", [k]),
	sprintf("The blueprint schema has no '%s'; CreateBlueprint fails with \"Request has invalid blueprint schema\"", [k]),
	"Give the schema class, description, type: object and a properties map of fields (each with type, inferenceType and instruction)",
	"https://docs.aws.amazon.com/bedrock/latest/userguide/bda-blueprint-info.html") if {
	some name in resources_of_type("AWS::Bedrock::Blueprint")
	s := object.get(_pf_bedrocklib_props(name), "Schema", null)
	is_object(s)
	some k in ["class", "description", "properties"]
	not _pf_bedrocklib_has(s, k)
}
