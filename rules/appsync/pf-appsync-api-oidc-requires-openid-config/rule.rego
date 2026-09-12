package cdk_preflight

import rego.v1

_pf_apioidcrequiresopenidconfig_absent(n, k) if {
	props := input.resources[n].properties
	is_object(props)
	object.get(props, k, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-appsync-api-oidc-requires-openid-config", "ERROR", name,
	"Properties.OpenIDConnectConfig",
	"AuthenticationType is OPENID_CONNECT but OpenIDConnectConfig is not set; the API create fails because AppSync has no OIDC provider to validate tokens against",
	"Set Properties.OpenIDConnectConfig, or pick a different AuthenticationType",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-appsync-graphqlapi.html") if {
	some name in resources_of_type("AWS::AppSync::GraphQLApi")
	resolve(name, "Properties.AuthenticationType") == "OPENID_CONNECT"
	_pf_apioidcrequiresopenidconfig_absent(name, "OpenIDConnectConfig")
}
