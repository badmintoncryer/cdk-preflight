package cdk_preflight

import rego.v1

# The vendor enum and the config union are independent in the schema; the
# service requires the matching block ("Provided configuration does not match
# selected type"). Vendors without a dedicated block (Okta, Auth0, Cognito,
# ...) use IncludedOauth2ProviderConfig.
_pf_oavc_block := {
	"CustomOauth2": "CustomOauth2ProviderConfig",
	"GoogleOauth2": "GoogleOauth2ProviderConfig",
	"GithubOauth2": "GithubOauth2ProviderConfig",
	"SlackOauth2": "SlackOauth2ProviderConfig",
	"SalesforceOauth2": "SalesforceOauth2ProviderConfig",
	"MicrosoftOauth2": "MicrosoftOauth2ProviderConfig",
	"AtlassianOauth2": "AtlassianOauth2ProviderConfig",
	"LinkedinOauth2": "LinkedinOauth2ProviderConfig",
}

_pf_oavc_expected(vendor) := _pf_oavc_block[vendor]

_pf_oavc_expected(vendor) := "IncludedOauth2ProviderConfig" if not _pf_oavc_block[vendor]

violation contains make_diag_full("pf-agentcore-oauth2-provider-vendor-config", "ERROR", name,
	"Properties.Oauth2ProviderConfigInput",
	sprintf("CredentialProviderVendor is %s but Oauth2ProviderConfigInput has no %s; CreateOauth2CredentialProvider fails with \"Provided configuration does not match selected type: %s\"", [vendor, expected, vendor]),
	sprintf("Add Oauth2ProviderConfigInput.%s (ClientId, ClientSecret, and for Custom / Included the OauthDiscovery)", [expected]),
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateOauth2CredentialProvider.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::OAuth2CredentialProvider")
	vendor := resolve(name, "Properties.CredentialProviderVendor")
	is_string(vendor)
	expected := _pf_oavc_expected(vendor)
	props := input.resources[name].properties
	is_object(props)
	inp := object.get(props, "Oauth2ProviderConfigInput", null)
	is_object(inp)
	object.get(inp, expected, "__pf_absent") == "__pf_absent"
}
