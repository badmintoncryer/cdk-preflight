package cdk_preflight

import rego.v1

# EKS passes this role from the caller's own account, so a foreign role comes
# back as AccessDeniedException - which reads like a missing permission rather
# than a wrong ARN. TargetRoleArn is the supported cross-account path.
violation contains make_diag_full("pf-eks-podidentity-role-arn-account", "ERROR", name,
	"Properties.RoleArn",
	sprintf("RoleArn names a role in account %v but the stack deploys to %v (\"Cross-account pass role is not allowed.\")", [arnAccount, account]),
	"Reference an IAM role in the deploy account and reach the other account through TargetRoleArn",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-podidentityassociation.html") if {
	some name in resources_of_type("AWS::EKS::PodIdentityAssociation")
	account := data.cdk_preflight.deploy_account
	is_string(account)
	arn := resolve(name, "Properties.RoleArn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "iam"
	arnAccount := parts[4]
	arnAccount != ""
	arnAccount != account
}
