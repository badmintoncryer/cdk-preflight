package cdk_preflight

import rego.v1

# Measured 2026-09-25: a STANDARD entry takes a principal from another
# account, the five node types do not. data.cdk_preflight.deploy_account is
# defined only in enforce mode with a concrete account, otherwise this skips.
violation contains make_diag_full("pf-eks-accessentry-principal-arn-account", "ERROR", name,
	"Properties.PrincipalArn",
	sprintf("a %v access entry names a principal in account %v but the stack deploys to %v (\"AccessEntry principalArn must be from the same account as the cluster when using types [EC2_LINUX, EC2_WINDOWS, FARGATE_LINUX, HYBRID_LINUX, EC2]\")", [t, arnAccount, account]),
	"Reference an IAM role in the deploy account, or use type STANDARD for a principal from another account",
	"https://docs.aws.amazon.com/eks/latest/userguide/creating-access-entries.html") if {
	some name in resources_of_type("AWS::EKS::AccessEntry")
	t := resolve(name, "Properties.Type")
	t in {"EC2", "EC2_LINUX", "EC2_WINDOWS", "FARGATE_LINUX", "HYBRID_LINUX"}
	account := data.cdk_preflight.deploy_account
	is_string(account)
	arn := resolve(name, "Properties.PrincipalArn")
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "iam"
	arnAccount := parts[4]
	arnAccount != ""
	arnAccount != account
}
