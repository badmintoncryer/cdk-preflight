package cdk_preflight

import rego.v1

# Components is required but the schema has no minProperties; an empty map
# fails at CreateConfigurationBundle ("Components map cannot be empty").
violation contains make_diag_full("pf-agentcore-config-bundle-components-empty", "ERROR", name,
	"Properties.Components",
	"Components is empty; CreateConfigurationBundle fails with \"Components map cannot be empty. At least one component configuration is required\"",
	"Add at least one component (e.g. a harness configuration)",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateConfigurationBundle.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::ConfigurationBundle")
	c := resolve(name, "Properties.Components")
	is_object(c)
	count(c) == 0
}
