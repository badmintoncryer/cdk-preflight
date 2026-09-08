package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-logs-subscription-lambda-no-role", "ERROR", name,
	"Properties.RoleArn",
	"The subscription filter targets a Lambda function and also sets RoleArn; PutSubscriptionFilter fails with \"destinationArn for vendor lambda cannot be used with roleArn\"",
	"Drop RoleArn and grant logs.amazonaws.com invoke permission on the function instead (AWS::Lambda::Permission)",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/SubscriptionFilters.html") if {
	some name in resources_of_type("AWS::Logs::SubscriptionFilter")
	_pf_lglib_dest_vendor(name) == "lambda"
	not _pf_lglib_absent(name, "RoleArn")
}
