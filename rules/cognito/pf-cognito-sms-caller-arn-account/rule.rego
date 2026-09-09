package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_account is injected only in enforce mode with a
# concrete account; the rule skips otherwise.

violation contains make_diag_full("pf-cognito-sms-caller-arn-account", "ERROR", name,
	"Properties.SmsConfiguration.SnsCallerArn",
	sprintf("SnsCallerArn is in account %v but the pool deploys to %v; the pool create fails with \"Cross-account pass role is not allowed.\"", [a, acct]),
	"Use an SNS caller role from the same account as the user pool",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpool.html") if {
	some name in resources_of_type("AWS::Cognito::UserPool")
	acct := data.cdk_preflight.deploy_account
	is_string(acct)
	arn := resolve(name, "Properties.SmsConfiguration.SnsCallerArn")
	a := _pf_coglib_arn_account(arn)
	a != acct
}
