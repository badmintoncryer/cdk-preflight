package cdk_preflight

import rego.v1

# CreateConfigurationBundle rejects a name already present in the account (409,
# measured 2026-09-10). E3019 reads primaryIdentifier (the read-only BundleArn),
# so BundleName is invisible to the engine.
violation contains make_diag_full("pf-agentcore-config-bundle-name-unique", "ERROR", name,
	"Properties.BundleName",
	sprintf("BundleName '%s' is already used by resource '%s'; CreateConfigurationBundle fails with \"A configuration bundle with this name already exists\"", [bn, other]),
	"Give each configuration bundle a distinct name",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateConfigurationBundle.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::ConfigurationBundle")
	bn := resolve(name, "Properties.BundleName")
	is_string(bn)
	some other in resources_of_type("AWS::BedrockAgentCore::ConfigurationBundle")
	other < name
	resolve(other, "Properties.BundleName") == bn
}
