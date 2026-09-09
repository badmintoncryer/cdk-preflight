package cdk_preflight

import rego.v1

# The key is <provider>:<client id> for a user pool provider, or the provider
# domain for a social one - always a dotted name.

violation contains make_diag_full("pf-cognito-role-mappings-key-format", "ERROR", name,
	sprintf("Properties.RoleMappings.%s", [k]),
	sprintf("RoleMappings key '%s' is not a provider name; the roles call fails with \"(%s) is not a valid RoleMapping ProviderName or is not a configured provider.\"", [k, k]),
	"Use cognito-idp.<region>.amazonaws.com/<pool id>:<client id> (or the social provider domain)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-identitypoolroleattachment.html") if {
	some name in resources_of_type("AWS::Cognito::IdentityPoolRoleAttachment")
	rm := resolve(name, "Properties.RoleMappings")
	is_object(rm)
	some k, _ in rm
	is_string(k)
	not contains(k, ".")
}
