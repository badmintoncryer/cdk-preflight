package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-api-oidc-issuer-scheme", "ERROR", name,
	"Properties.OpenIDConnectConfig.Issuer",
	sprintf("OpenIDConnectConfig.Issuer '%s' is not an https URL; the API create fails because AppSync fetches the OIDC discovery document over https", [iss]),
	"Use the issuer's https:// URL",
	"https://docs.aws.amazon.com/appsync/latest/APIReference/API_OpenIDConnectConfig.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	iss := resolve(name, "Properties.OpenIDConnectConfig.Issuer")
	is_string(iss)
	not startswith(iss, "https://")
}
