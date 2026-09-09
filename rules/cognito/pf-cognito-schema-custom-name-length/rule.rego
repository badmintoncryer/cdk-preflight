package cdk_preflight

import rego.v1

# The custom: prefix is added by the service and does not count towards the cap.

violation contains make_diag_full("pf-cognito-schema-custom-name-length", "ERROR", name,
	sprintf("Properties.Schema.%d.Name", [a.index]),
	sprintf("schema attribute name '%s' is %d characters; the pool create fails with \"Value '%s' at 'schema.1.member.name' failed to satisfy constraint: Member must have length less than or equal to 20\"", [n, count(n), n]),
	"Use an attribute name of at most 20 characters",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	some a in flatten_list(name, "Properties.Schema")
	is_object(a.value)
	n := object.get(a.value, "Name", "")
	is_string(n)
	count(n) > 20
}
