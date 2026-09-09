package cdk_preflight

import rego.v1

# The tier lives on the user pool, the version on the domain: no single
# resource carries both.

violation contains make_diag_full("pf-cognito-managed-login-version-tier", "ERROR", name,
	"Properties.ManagedLoginVersion",
	"ManagedLoginVersion 2 on a LITE user pool; the domain create fails with \"The following feature is not available for the LITE pricing tier configured: Managed Login Version 2\"",
	"Use UserPoolTier ESSENTIALS or PLUS on the pool, or ManagedLoginVersion 1",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpooldomain.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolDomain")
	to_number(resolve(name, "Properties.ManagedLoginVersion")) == 2
	pool := resolve(name, "Properties.UserPoolId")
	pool in resources_of_type("AWS::Cognito::UserPool")
	resolve(pool, "Properties.UserPoolTier") == "LITE"
}
