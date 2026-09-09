package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cognito-schema-name-duplicate", "ERROR", name,
	sprintf("Properties.Schema.%d.Name", [b.index]),
	sprintf("Schema declares the attribute '%s' twice; the pool create fails with \"Duplicate custom attribute names custom:%s are not allowed in a user pool schema.\"", [n, n]),
	"Give each schema attribute a distinct Name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	some a in flatten_list(name, "Properties.Schema")
	some b in flatten_list(name, "Properties.Schema")
	a.index < b.index
	is_object(a.value)
	is_object(b.value)
	n := object.get(a.value, "Name", "__pf_a")
	is_string(n)
	n == object.get(b.value, "Name", "__pf_b")
}
