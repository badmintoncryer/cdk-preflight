package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appsync-ds-eventbus-arn-region", "ERROR", name,
	"Properties.EventBridgeConfig.EventBusArn",
	sprintf("the event bus is in region '%s' but this stack deploys to '%s'; the data source create fails because AppSync only publishes to a bus in its own region", [parts[3], region]),
	"Use an event bus in the region this stack deploys to",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-appsync-datasource.html") if {
	some name in resources_of_type("AWS::AppSync::DataSource")
	region := data.cdk_preflight.deploy_region
	arn := resolve(name, "Properties.EventBridgeConfig.EventBusArn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) > 3
	parts[2] == "events"
	parts[3] != region
}
