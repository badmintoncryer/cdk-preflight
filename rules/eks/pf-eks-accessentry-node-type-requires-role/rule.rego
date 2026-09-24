package cdk_preflight

import rego.v1

# Measured 2026-09-25 against CreateAccessEntry with a user ARN in the deploy
# account: all five node types are refused, STANDARD reaches the cluster
# lookup. Separate from -principal-arn-account, which is about the account.
violation contains make_diag_full("pf-eks-accessentry-node-type-requires-role", "ERROR", name,
	"Properties.PrincipalArn",
	sprintf("a %v access entry names an IAM user (\"AccessEntry principalArn must be IAM role when using types [EC2_LINUX, EC2_WINDOWS, FARGATE_LINUX, HYBRID_LINUX, EC2]\")", [t]),
	"Point PrincipalArn at the node IAM role, or use type STANDARD for a user",
	"https://docs.aws.amazon.com/eks/latest/userguide/creating-access-entries.html") if {
	some name in resources_of_type("AWS::EKS::AccessEntry")
	t := resolve(name, "Properties.Type")
	t in {"EC2", "EC2_LINUX", "EC2_WINDOWS", "FARGATE_LINUX", "HYBRID_LINUX"}
	_pf_eksae_user(name)
}

_pf_eksae_user(name) if {
	arn := resolve(name, "Properties.PrincipalArn")
	_pf_ekslib_lit(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[2] == "iam"
	startswith(parts[5], "user/")
}

_pf_eksae_user(name) if {
	u := resolve(name, "Properties.PrincipalArn")
	u in resources_of_type("AWS::IAM::User")
}
