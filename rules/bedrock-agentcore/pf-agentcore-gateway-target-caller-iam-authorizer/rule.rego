package cdk_preflight

import rego.v1

# Any target may list CALLER_IAM_CREDENTIALS in the schema, but the gateway
# then has to authenticate callers with IAM (dev guide note); CreateGatewayTarget
# fails with "CALLER_IAM_CREDENTIALS credential provider type requires the
# gateway authorizer type to be AWS_IAM, or AUTHENTICATE_ONLY". Checked only
# when the gateway is in the same template.
violation contains make_diag_full("pf-agentcore-gateway-target-caller-iam-authorizer", "ERROR", name,
	sprintf("Properties.CredentialProviderConfigurations.%d.CredentialProviderType", [c.index]),
	sprintf("Gateway '%s' uses AuthorizerType %s; CreateGatewayTarget fails with \"CALLER_IAM_CREDENTIALS credential provider type requires the gateway authorizer type to be AWS_IAM, or AUTHENTICATE_ONLY\"", [gw, auth]),
	"Set the gateway's AuthorizerType to AWS_IAM or AUTHENTICATE_ONLY, or use another credential provider type",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-building-adding-targets-authorization.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayTarget")
	some c in flatten_list(name, "Properties.CredentialProviderConfigurations")
	object.get(c.value, "CredentialProviderType", null) == "CALLER_IAM_CREDENTIALS"
	gw := _pf_bedrocklib_ref_target(resolve(name, "Properties.GatewayIdentifier"), "AWS::BedrockAgentCore::Gateway")
	auth := resolve(gw, "Properties.AuthorizerType")
	is_string(auth)
	not auth in {"AWS_IAM", "AUTHENTICATE_ONLY"}
}
