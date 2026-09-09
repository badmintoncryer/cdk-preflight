package cdk_preflight

import rego.v1

# The domain lives on a separate resource, so nothing but a template-wide view
# can see that it is missing.

_pf_cgucrd_has_domain(pool) if {
	some d in resources_of_type("AWS::Cognito::UserPoolDomain")
	resolve(d, "Properties.UserPoolId") == pool
}

violation contains make_diag_full("pf-cognito-ui-customization-requires-domain", "ERROR", name,
	"Properties.UserPoolId",
	"The pool has no AWS::Cognito::UserPoolDomain in this template; the UI customization call fails with \"A domain must be associated with this user pool.\"",
	"Add an AWS::Cognito::UserPoolDomain for the pool (and DependsOn it)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpooluicustomizationattachment.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolUICustomizationAttachment")
	pool := resolve(name, "Properties.UserPoolId")
	pool in resources_of_type("AWS::Cognito::UserPool")
	not _pf_cgucrd_has_domain(pool)
}
