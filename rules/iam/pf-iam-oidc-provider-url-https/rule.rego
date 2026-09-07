package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-iam-oidc-provider-url-https", "ERROR", name,
	"Properties.Url",
	sprintf("OIDC provider Url '%s' is not https; IAM rejects the provider with InvalidInput", [v]),
	"Use the issuer URL exactly as it appears in the provider's iss claim, which is always https://",
	"https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateOpenIDConnectProvider.html") if {
	some name in resources_of_type("AWS::IAM::OIDCProvider")
	v := resolve(name, "Properties.Url")
	is_string(v)
	not startswith(v, "https://")
}
