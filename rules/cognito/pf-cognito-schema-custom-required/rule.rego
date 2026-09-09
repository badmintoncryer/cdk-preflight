package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-schema-custom-required", "ERROR", name,
	sprintf("Properties.Schema.%d.Required", [a.index]),
	sprintf("custom attribute '%s' is marked Required; the pool create fails with \"Required custom attributes are not supported currently.\"", [n]),
	"Drop Required from the custom attribute (only standard attributes can be required)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	some a in flatten_list(name, "Properties.Schema")
	is_object(a.value)
	n := object.get(a.value, "Name", "")
	not n in _pf_coglib_std_attrs
	object.get(a.value, "Required", false) == true
}
