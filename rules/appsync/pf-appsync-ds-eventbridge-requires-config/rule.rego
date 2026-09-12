package cdk_preflight

import rego.v1

_pf_dseventbridgerequiresconfig_absent(n, k) if {
	props := input.resources[n].properties
	is_object(props)
	object.get(props, k, "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-appsync-ds-eventbridge-requires-config", "ERROR", name,
	"Properties.EventBridgeConfig",
	"Type is AMAZON_EVENTBRIDGE but EventBridgeConfig is not set; the data source create has nothing to connect to",
	"Set Properties.EventBridgeConfig, or use a different Type",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-datasource.html") if {
	some name in resources_of_type("AWS::AppSync::DataSource")
	resolve(name, "Properties.Type") == "AMAZON_EVENTBRIDGE"
	_pf_dseventbridgerequiresconfig_absent(name, "EventBridgeConfig")
}
