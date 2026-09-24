package cdk_preflight

import rego.v1

# The check is on the ARN shape alone - measured 2026-09-25 for the deploy
# account and for a foreign one, and for STANDARD as well as node types.
violation contains make_diag_full("pf-eks-accessentry-principal-arn-service-linked-role", "ERROR", name,
	"Properties.PrincipalArn",
	sprintf("PrincipalArn %v is a service-linked role (\"The caller is not allowed to modify access entries with a principalArn value of a Service Linked Role\")", [arn]),
	"Point PrincipalArn at a customer-managed IAM role or user",
	"https://docs.aws.amazon.com/eks/latest/userguide/creating-access-entries.html") if {
	some name in resources_of_type("AWS::EKS::AccessEntry")
	arn := resolve(name, "Properties.PrincipalArn")
	_pf_ekslib_lit(arn)
	contains(arn, ":role/aws-service-role/")
}
