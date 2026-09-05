package cdk_preflight

import rego.v1

# ApiKey, ApiKeySecretSource and ApiKeySecretConfig are three independent
# optional fields in the schema; the service ties them together at create
# time. Presence is read from the preprocessed document so a Ref / dynamic
# reference still counts as present.
_pf_akpsrc_url := "https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateApiKeyCredentialProvider.html"

_pf_akpsrc_has(name, key) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, key, "__pf_absent") != "__pf_absent"
}

_pf_akpsrc_external(name) if resolve(name, "Properties.ApiKeySecretSource") == "EXTERNAL"

violation contains make_diag_full("pf-agentcore-apikey-provider-secret-source", "ERROR", name,
	"Properties.ApiKey",
	"ApiKeySecretSource is MANAGED (the default) but ApiKey is missing; CreateApiKeyCredentialProvider fails with \"ApiKey is required when secret source is MANAGED or not specified\"",
	"Set ApiKey, or set ApiKeySecretSource: EXTERNAL and point ApiKeySecretConfig at a Secrets Manager secret",
	_pf_akpsrc_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::ApiKeyCredentialProvider")
	not _pf_akpsrc_external(name)
	not _pf_akpsrc_has(name, "ApiKey")
}

violation contains make_diag_full("pf-agentcore-apikey-provider-secret-source", "ERROR", name,
	"Properties.ApiKeySecretConfig",
	"ApiKeySecretSource is MANAGED (the default) but ApiKeySecretConfig is set; CreateApiKeyCredentialProvider fails with \"ApiKeySecretConfig must not be provided when secret source is MANAGED or not specified\"",
	"Remove ApiKeySecretConfig, or set ApiKeySecretSource: EXTERNAL and drop ApiKey",
	_pf_akpsrc_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::ApiKeyCredentialProvider")
	not _pf_akpsrc_external(name)
	_pf_akpsrc_has(name, "ApiKeySecretConfig")
}

violation contains make_diag_full("pf-agentcore-apikey-provider-secret-source", "ERROR", name,
	"Properties.ApiKeySecretConfig",
	"ApiKeySecretSource is EXTERNAL but ApiKeySecretConfig is missing; CreateApiKeyCredentialProvider fails with \"ApiKeySecretConfig is required when secret source is EXTERNAL\"",
	"Add ApiKeySecretConfig (SecretId and JsonKey of the Secrets Manager secret holding the key)",
	_pf_akpsrc_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::ApiKeyCredentialProvider")
	_pf_akpsrc_external(name)
	not _pf_akpsrc_has(name, "ApiKeySecretConfig")
}

violation contains make_diag_full("pf-agentcore-apikey-provider-secret-source", "ERROR", name,
	"Properties.ApiKey",
	"ApiKeySecretSource is EXTERNAL but ApiKey is also set; CreateApiKeyCredentialProvider fails with \"ApiKey must not be provided when secret source is EXTERNAL\"",
	"Remove ApiKey and keep only ApiKeySecretConfig",
	_pf_akpsrc_url) if {
	some name in resources_of_type("AWS::BedrockAgentCore::ApiKeyCredentialProvider")
	_pf_akpsrc_external(name)
	_pf_akpsrc_has(name, "ApiKey")
}
