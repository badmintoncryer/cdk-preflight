package cdk_preflight

import rego.v1

# Needs the deploy environment (enforce mode with a concrete account).
violation contains make_diag_full("pf-cloudwatch-metric-stream-role-account", "ERROR", name,
	"Properties.RoleArn",
	sprintf("RoleArn names account %s but the stack deploys to %s; PutMetricStream fails with \"Cross-account pass role is not allowed.\"", [arn_account, account]),
	"Pass a role from this account (build the ARN with ${AWS::AccountId})",
	"https://docs.aws.amazon.com/AmazonCloudWatch/latest/APIReference/API_PutMetricStream.html") if {
	account := data.cdk_preflight.deploy_account
	some name in resources_of_type("AWS::CloudWatch::MetricStream")
	parts := _pf_cwlib_arn(resolve(name, "Properties.RoleArn"))
	parts[2] == "iam"
	arn_account := parts[4]
	arn_account != account
}
