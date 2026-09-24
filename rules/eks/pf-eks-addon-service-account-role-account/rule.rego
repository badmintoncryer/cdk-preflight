package cdk_preflight

import rego.v1

# EKS passes this role to the add-on from the caller's own account, so a role
# ARN in another account comes back as AccessDeniedException "Cross-account
# pass role is not allowed." - which reads like a missing IAM permission.
# data.cdk_preflight.deploy_account is defined only in enforce mode with a
# concrete account, otherwise this rule skips.
violation contains make_diag_full("pf-eks-addon-service-account-role-account", "ERROR", name,
	"Properties.ServiceAccountRoleArn",
	sprintf("ServiceAccountRoleArn names a role in account %v but the stack deploys to %v (\"Cross-account pass role is not allowed.\")", [roleAccount, account]),
	"Reference an IAM role in the deploy account",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-addon.html") if {
	some name in resources_of_type("AWS::EKS::Addon")
	account := data.cdk_preflight.deploy_account
	is_string(account)
	arn := resolve(name, "Properties.ServiceAccountRoleArn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "iam"
	roleAccount := parts[4]
	roleAccount != ""
	roleAccount != account
}
