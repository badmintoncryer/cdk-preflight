package cdk_preflight

import rego.v1

# BundleArn takes any account in the schema, but CreateGatewayRule fails
# with "Configuration bundle must belong to the same account as the gateway"
# for a WeightedOverride bundle of another account (the bundle's existence is
# not checked). StaticOverride is not measured and not checked.
# data.cdk_preflight.deploy_account is defined only in enforce mode with a
# concrete account, otherwise this rule skips.
violation contains make_diag_full("pf-agentcore-gateway-rule-bundle-account", "ERROR", name,
	sprintf("Properties.Actions.%d.ConfigurationBundle.WeightedOverride.TrafficSplit.%d.ConfigurationBundle.BundleArn", [i, j]),
	sprintf("The configuration bundle belongs to account %s but the gateway is in %s; CreateGatewayRule fails with \"Configuration bundle must belong to the same account as the gateway\"", [acct, account]),
	"Reference a configuration bundle in the gateway's own account",
	"https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-rules.html") if {
	some name in resources_of_type("AWS::BedrockAgentCore::GatewayRule")
	account := data.cdk_preflight.deploy_account
	is_string(account)
	some a in flatten_list(name, "Properties.Actions")
	i := a.index
	some s in flatten_list(name, sprintf("Properties.Actions.%d.ConfigurationBundle.WeightedOverride.TrafficSplit", [i]))
	j := s.index
	arn := resolve(name, sprintf("Properties.Actions.%d.ConfigurationBundle.WeightedOverride.TrafficSplit.%d.ConfigurationBundle.BundleArn", [i, j]))
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	acct := parts[4]
	regex.match(`^[0-9]{12}$`, acct)
	acct != account
}
