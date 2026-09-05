package cdk_preflight

import rego.v1

# CredentialProviderType and CredentialProvider are independent schema fields;
# the pairing is only enforced by CreateGatewayTarget ("OAuth credential
# provider is required for OAUTH credential provider type" / "API key
# credential provider is required for API_KEY credential provider type").
_pf_gwtcred_block := {"OAUTH": "OauthCredentialProvider", "API_KEY": "ApiKeyCredentialProvider"}

_pf_gwtcred_has(c, key) if {
	cp := object.get(c, "CredentialProvider", null)
	is_object(cp)
	is_object(object.get(cp, key, null))
}

violation contains make_diag_full("pf-agentcore-gateway-target-credential-provider-required", "ERROR", name,
	sprintf("Properties.CredentialProviderConfigurations.%d.CredentialProvider", [c.index]),
	sprintf("CredentialProviderType is %s but CredentialProvider.%s is missing; CreateGatewayTarget fails with \"%s credential provider is required for %s credential provider type\"", [t, key, label, t]),
	sprintf("Add CredentialProvider.%s with the credential provider ProviderArn", [key]),
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CredentialProviderConfiguration.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayTarget")
	some c in flatten_list(name, "Properties.CredentialProviderConfigurations")
	t := object.get(c.value, "CredentialProviderType", null)
	key := _pf_gwtcred_block[t]
	label := {"OAUTH": "OAuth", "API_KEY": "API key"}[t]
	not _pf_gwtcred_has(c.value, key)
}
