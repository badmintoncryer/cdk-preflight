package cdk_preflight

import rego.v1

# EKS access policies are managed by EKS, not by IAM: their ARNs carry no
# account and live under the eks service. Pasting an IAM policy ARN here is
# the mistake the service reports.
violation contains make_diag_full("pf-eks-accessentry-policy-arn-form", "ERROR", name,
	sprintf("Properties.AccessPolicies.%v.PolicyArn", [ap.index]),
	sprintf("PolicyArn %v is not an EKS cluster access policy (\"The policyArn parameter format is not valid\")", [arn]),
	"Use arn:<partition>:eks::aws:cluster-access-policy/<Name>; EKS access policies are not IAM policies",
	"https://docs.aws.amazon.com/eks/latest/userguide/access-policies.html") if {
	some name in resources_of_type("AWS::EKS::AccessEntry")
	some ap in flatten_list(name, "Properties.AccessPolicies")
	arn := _pf_ekslib_oget(ap.value, "PolicyArn")
	_pf_ekslib_lit(arn)
	not regex.match(`^arn:[^:]+:eks::aws:cluster-access-policy/.+$`, arn)
}
