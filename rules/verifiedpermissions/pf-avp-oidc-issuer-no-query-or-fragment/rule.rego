package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-oidc-issuer-no-query-or-fragment", "ERROR", name, "Properties.Configuration.OpenIdConnectConfiguration.Issuer",
	sprintf("Issuer %v carries a query string or fragment; Verified Permissions appends \"/.well-known/openid-configuration\" to it verbatim and CreateIdentitySource answers \"Failed to deserialize discovery document from issuer\"", [iss]),
	"Give Issuer the bare origin (and path) of the provider, with no ? or # in it",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-verifiedpermissions-identitysource.html") if {
	some name in resources_of_type("AWS::VerifiedPermissions::IdentitySource")
	iss := resolve(name, "Properties.Configuration.OpenIdConnectConfiguration.Issuer")
	is_string(iss)
	startswith(iss, "https://")
	regex.match(`[?#]`, iss)
}
