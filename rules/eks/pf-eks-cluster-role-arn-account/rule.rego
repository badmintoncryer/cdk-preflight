package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_account is injected only in enforce mode with a
# concrete account; the rule skips otherwise. A Fn::GetAtt resolves to a
# logical id, which has no account to compare, so in-template roles are silent.
violation contains make_diag_full("pf-eks-cluster-role-arn-account", "ERROR", name,
	"Properties.RoleArn",
	sprintf("the cluster role is in account %v but the stack deploys to %v (\"Cross-account pass role is not allowed.\")", [arnAccount, account]),
	"Reference a cluster role in the deploy account",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-eks-cluster.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
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
