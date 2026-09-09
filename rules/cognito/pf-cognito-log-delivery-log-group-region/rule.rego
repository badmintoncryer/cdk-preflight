package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_region is injected only in enforce mode with a
# concrete region; the rule skips otherwise.

violation contains make_diag_full("pf-cognito-log-delivery-log-group-region", "ERROR", name,
	sprintf("Properties.LogConfigurations.%d.CloudWatchLogsConfiguration.LogGroupArn", [c.index]),
	sprintf("the log group is in '%v' but the pool deploys to '%v'; the log delivery call fails with \"ARN does not belong to current region\"", [r, region]),
	"Use a log group in the pool's own region",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-logdeliveryconfiguration.html") if {
	some name in resources_of_type("AWS::Cognito::LogDeliveryConfiguration")
	region := data.cdk_preflight.deploy_region
	is_string(region)
	some c in flatten_list(name, "Properties.LogConfigurations")
	arn := _pf_coglib_at2(c.value, "CloudWatchLogsConfiguration", "LogGroupArn")
	r := _pf_coglib_arn_region(arn)
	r != region
}
