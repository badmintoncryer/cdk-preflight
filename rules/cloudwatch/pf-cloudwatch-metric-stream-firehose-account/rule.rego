package cdk_preflight

import rego.v1

# Needs the deploy environment (enforce mode with a concrete account).
violation contains make_diag_full("pf-cloudwatch-metric-stream-firehose-account", "ERROR", name,
	"Properties.FirehoseArn",
	sprintf("FirehoseArn names account %s but the stack deploys to %s; PutMetricStream fails with \"FirehoseArn must be in the same account as the Metric Stream\"", [arn_account, account]),
	"Build the ARN with ${AWS::AccountId}; a metric stream cannot write to another account's delivery stream",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricStream.html") if {
	account := data.cdk_preflight.deploy_account
	some name in resources_of_type("AWS::CloudWatch::MetricStream")
	parts := _pf_cwlib_arn(resolve(name, "Properties.FirehoseArn"))
	parts[2] == "firehose"
	arn_account := parts[4]
	arn_account != account
}
