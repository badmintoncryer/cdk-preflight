package cdk_preflight

import rego.v1

# CustomOauth2ProviderConfig makes ClientSecret, ClientSecretSource and
# ClientSecretConfig independent optional fields; the service ties them
# together for the client-secret authentication methods (the default).
# PRIVATE_KEY_JWT is handled by pf-agentcore-oauth2-provider-private-key-jwt.
_pf_oacs_url := "https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CustomOauth2ProviderConfigInput.html"
_pf_oacs_path := "Properties.Oauth2ProviderConfigInput.CustomOauth2ProviderConfig"

_pf_oacs_cfg(name) := cfg if {
	props := input.resources[name].properties
	is_object(props)
	inp := object.get(props, "Oauth2ProviderConfigInput", null)
	is_object(inp)
	cfg := object.get(inp, "CustomOauth2ProviderConfig", null)
	is_object(cfg)
}

_pf_oacs_has(cfg, key) if object.get(cfg, key, "__pf_absent") != "__pf_absent"

_pf_oacs_secret_method(name) if {
	m := resolve(name, sprintf("%s.ClientAuthenticationMethod", [_pf_oacs_path]))
	m in {"CLIENT_SECRET_BASIC", "CLIENT_SECRET_POST"}
}

_pf_oacs_secret_method(name) if {
	not _pf_oacs_has(_pf_oacs_cfg(name), "ClientAuthenticationMethod")
}

_pf_oacs_external(name) if resolve(name, sprintf("%s.ClientSecretSource", [_pf_oacs_path])) == "EXTERNAL"

violation contains make_diag_full("pf-agentcore-oauth2-provider-client-secret", "ERROR", name,
	sprintf("%s.ClientSecret", [_pf_oacs_path]),
	"ClientSecretSource is MANAGED (the default) but ClientSecret is missing; CreateOauth2CredentialProvider fails with \"clientSecret is required for CLIENT_SECRET_BASIC and CLIENT_SECRET_POST authentication methods\"",
	"Set ClientSecret, or set ClientSecretSource: EXTERNAL and point ClientSecretConfig at a Secrets Manager secret",
	_pf_oacs_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::OAuth2CredentialProvider")
	cfg := _pf_oacs_cfg(name)
	_pf_oacs_secret_method(name)
	not _pf_oacs_external(name)
	not _pf_oacs_has(cfg, "ClientSecret")
}

violation contains make_diag_full("pf-agentcore-oauth2-provider-client-secret", "ERROR", name,
	sprintf("%s.ClientSecretConfig", [_pf_oacs_path]),
	"ClientSecretSource is EXTERNAL but ClientSecretConfig is missing; CreateOauth2CredentialProvider fails with \"clientSecretConfig is required for CLIENT_SECRET_BASIC and CLIENT_SECRET_POST authentication methods\"",
	"Add ClientSecretConfig (SecretId and JsonKey of the Secrets Manager secret holding the client secret)",
	_pf_oacs_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::OAuth2CredentialProvider")
	cfg := _pf_oacs_cfg(name)
	_pf_oacs_secret_method(name)
	_pf_oacs_external(name)
	not _pf_oacs_has(cfg, "ClientSecretConfig")
}

violation contains make_diag_full("pf-agentcore-oauth2-provider-client-secret", "ERROR", name,
	sprintf("%s.ClientSecret", [_pf_oacs_path]),
	"ClientSecretSource is EXTERNAL but ClientSecret is also set; CreateOauth2CredentialProvider fails with \"ClientSecret must not be provided when secret source is EXTERNAL\"",
	"Remove ClientSecret and keep only ClientSecretConfig",
	_pf_oacs_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::OAuth2CredentialProvider")
	cfg := _pf_oacs_cfg(name)
	_pf_oacs_external(name)
	_pf_oacs_has(cfg, "ClientSecret")
}
