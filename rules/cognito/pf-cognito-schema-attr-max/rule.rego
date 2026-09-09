package cdk_preflight

import rego.v1

# Standard attributes do not count; the cap is over the custom ones only.

violation contains make_diag_full("pf-cognito-schema-attr-max", "ERROR", name,
	"Properties.Schema",
	sprintf("the schema has %d custom attributes; the pool create fails with \"Member must have length less than or equal to 50\"", [count(attrs)]),
	"Keep the number of custom schema attributes at 50 or below",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	attrs := _pf_coglib_custom_attrs(name)
	count(attrs) > 50
}
