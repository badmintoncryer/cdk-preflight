package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_account is injected only in enforce mode with a
# concrete account; the rule skips otherwise.
violation contains make_diag_full("pf-opensearch-cognito-role-arn-account", "ERROR", name,
	"Properties.CognitoOptions.RoleArn",
	sprintf("the Cognito access role is in account %v but the stack deploys to %v; CreateDomain answers \"Cross-account pass role is not allowed.\"", [a, acct]),
	"Use a role from the account the domain deploys into",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/cognito-auth.html") if {
	some name in _pf_os_domains
	acct := data.cdk_preflight.deploy_account
	is_string(acct)
	a := _pf_os_arn_account(_pf_os_opt(name, "CognitoOptions", "RoleArn"))
	a != acct
}
