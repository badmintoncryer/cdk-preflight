package cdk_preflight

import rego.v1

# Mirror of pf-agentcore-gateway-jwt-authorizer: CUSTOM_JWT needs the block,
# AWS_IAM and NONE reject it ("AuthorizerConfiguration should be null for
# <type> AuthorizerType"). AUTHENTICATE_ONLY accepts either (measured
# 2026-09-05), so it is left alone. Presence is read from the preprocessed
# document so an unresolvable value still counts as present.
violation contains make_diag_full("pf-agentcore-gateway-authorizer-config-unexpected", "ERROR", name,
	"Properties.AuthorizerConfiguration",
	sprintf("AuthorizerType is %s but AuthorizerConfiguration is set; CreateGateway fails with \"AuthorizerConfiguration should be null for %s AuthorizerType\"", [t, t]),
	"Remove AuthorizerConfiguration, or switch AuthorizerType to CUSTOM_JWT if the JWT authorizer is intended",
	"https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateGateway.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::Gateway")
	t := resolve(name, "Properties.AuthorizerType")
	t in {"AWS_IAM", "NONE"}
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "AuthorizerConfiguration", "__pf_absent") != "__pf_absent"
}
