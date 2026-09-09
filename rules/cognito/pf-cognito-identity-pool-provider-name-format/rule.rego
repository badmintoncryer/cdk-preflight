package cdk_preflight

import rego.v1

# The pool id alone is the most common form of this mistake; the service wants
# cognito-idp.<region>.amazonaws.com/<pool id>.

violation contains make_diag_full("pf-cognito-identity-pool-provider-name-format", "ERROR", name,
	sprintf("Properties.CognitoIdentityProviders.%d.ProviderName", [p.index]),
	sprintf("ProviderName '%s' is not a cognito-idp endpoint; the identity pool create fails with \"Invalid Cognito Identity Provider\"", [n]),
	"Use cognito-idp.<region>.amazonaws.com/<user pool id>",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-identitypool.html") if {
	some name in resources_of_type("AWS::Cognito::IdentityPool")
	some p in flatten_list(name, "Properties.CognitoIdentityProviders")
	is_object(p.value)
	n := object.get(p.value, "ProviderName", "")
	is_string(n)
	n != ""
	not regex.match(`^cognito-idp\.[a-z0-9-]+\.amazonaws\.com/[a-z]{2}(-[a-z]+)+-[0-9]+_[A-Za-z0-9]+$`, n)
}
