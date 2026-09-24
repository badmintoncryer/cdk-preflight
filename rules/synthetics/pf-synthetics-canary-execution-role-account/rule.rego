package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-synthetics-canary-execution-role-account", "ERROR", name,
	"Properties.ExecutionRoleArn",
	sprintf("ExecutionRoleArn names a role in account '%s' but the stack deploys to '%s'; Synthetics will not pass a role across accounts and CreateCanary answers \"Cross-account pass role is not allowed.\"", [roleAccount, account]),
	"Reference a role in the deploy account",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-synthetics-canary.html") if {
	some name in resources_of_type("AWS::Synthetics::Canary")
	account := data.cdk_preflight.deploy_account
	is_string(account)
	arn := resolve(name, "Properties.ExecutionRoleArn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "iam"
	roleAccount := parts[4]
	roleAccount != ""
	roleAccount != account
}
