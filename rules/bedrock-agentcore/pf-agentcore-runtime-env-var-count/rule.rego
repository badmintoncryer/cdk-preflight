package cdk_preflight

import rego.v1

# The registry schema sets maxProperties: 50 on EnvironmentVariables and
# CloudFormation's early validation rolls the stack back; the bundled engine
# (1.7.0-beta) checks key patterns (F3002) but not the map size.
violation contains make_diag_full("pf-agentcore-runtime-env-var-count", "ERROR", name,
	"Properties.EnvironmentVariables",
	sprintf("%d environment variables are set but the runtime accepts at most 50; CloudFormation rejects the template (PROPERTY_VALIDATION: maximum size 50)", [count(env)]),
	"Trim EnvironmentVariables to 50 entries or move configuration into a parameter store / config file",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateAgentRuntime.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Runtime")
	env := resolve(name, "Properties.EnvironmentVariables")
	is_object(env)
	count(env) > 50
}
