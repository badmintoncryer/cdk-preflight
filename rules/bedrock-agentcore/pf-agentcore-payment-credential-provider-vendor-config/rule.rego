package cdk_preflight

import rego.v1

# Same shape as pf-agentcore-oauth2-provider-vendor-config for the payment
# vendors: the enum and the config union are independent in the schema.
_pf_pcpvc_block := {"CoinbaseCDP": "CoinbaseCdpConfiguration", "StripePrivy": "StripePrivyConfiguration"}

violation contains make_diag_full("pf-agentcore-payment-credential-provider-vendor-config", "ERROR", name,
	"Properties.ProviderConfigurationInput",
	sprintf("CredentialProviderVendor is %s but ProviderConfigurationInput has no %s; CreatePaymentCredentialProvider fails with \"%s vendor type requires %s in providerConfigurationInput\"", [vendor, expected, vendor, lower(substring(expected, 0, 1))]),
	sprintf("Add ProviderConfigurationInput.%s with that vendor's credentials", [expected]),
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreatePaymentCredentialProvider.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::PaymentCredentialProvider")
	vendor := resolve(name, "Properties.CredentialProviderVendor")
	expected := _pf_pcpvc_block[vendor]
	props := input.resources[name].properties
	is_object(props)
	inp := object.get(props, "ProviderConfigurationInput", null)
	is_object(inp)
	object.get(inp, expected, "__pf_absent") == "__pf_absent"
}
