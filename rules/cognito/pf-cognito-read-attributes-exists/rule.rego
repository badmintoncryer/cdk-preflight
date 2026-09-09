package cdk_preflight

import rego.v1

# Judged only when the pool is a sibling resource, so its Schema is visible here.

_pf_cgrae_declared(pool, v) if {
	some att in flatten_list(pool, "Properties.Schema")
	is_object(att.value)
	n := object.get(att.value, "Name", "")
	v in {n, concat("", ["custom:", n]), concat("", ["dev:custom:", n])}
}

violation contains make_diag_full("pf-cognito-read-attributes-exists", "ERROR", name,
	sprintf("Properties.ReadAttributes.%d", [a.index]),
	sprintf("ReadAttributes has '%s', which the pool does not define; the client create fails with \"Invalid read attributes specified while creating a client\"", [v]),
	"Declare the attribute in the pool Schema, or drop it from ReadAttributes",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolclient.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolClient")
	pool := resolve(name, "Properties.UserPoolId")
	pool in resources_of_type("AWS::Cognito::UserPool")
	some a in flatten_list(name, "Properties.ReadAttributes")
	v := a.value
	is_string(v)
	not v in _pf_coglib_std_attrs
	not _pf_cgrae_declared(pool, v)
}
