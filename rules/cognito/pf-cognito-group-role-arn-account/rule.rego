package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_account is injected only in enforce mode with a
# concrete account; the rule skips otherwise.

violation contains make_diag_full("pf-cognito-group-role-arn-account", "ERROR", name,
	"Properties.RoleArn",
	sprintf("the group role is in account %v but the pool deploys to %v; the group create fails with \"Cross-account pass role is not allowed.\"", [a, acct]),
	"Use a role from the same account as the user pool",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-cognito-userpoolgroup.html") if {
	some name in resources_of_type("AWS::Cognito::UserPoolGroup")
	acct := data.cdk_preflight.deploy_account
	is_string(acct)
	a := _pf_coglib_arn_account(resolve(name, "Properties.RoleArn"))
	a != acct
}
