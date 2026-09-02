package cdk_preflight

import rego.v1

# The Schema body is opaque JSON to every schema layer. Full draft-4
# validation is out of scope; a literal top-level "type" outside the
# draft-4 set (a common typo like "String") is provably fatal.
_pf_apgmst_types := {"array", "boolean", "integer", "null", "number", "object", "string"}

violation contains make_diag_full("pf-apigw-model-schema-type", "ERROR", name,
	"Properties.Schema.type",
	sprintf("Model schema type '%s' is not a JSON Schema draft-4 type; the model create fails with \"Invalid model specified: Validation Result: warnings : [], errors : [Invalid model schema specified]\"", [t]),
	"Use one of array, boolean, integer, null, number, object, string (lowercase)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-apigateway-model.html") if {
	some name in resources_of_type("AWS::ApiGateway::Model")
	sch := resolve(name, "Properties.Schema")
	is_object(sch)
	t := object.get(sch, "type", "__pf_absent")
	t != "__pf_absent"
	is_string(t)
	not t in _pf_apgmst_types
}
