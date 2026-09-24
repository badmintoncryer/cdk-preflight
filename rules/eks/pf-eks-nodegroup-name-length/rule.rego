package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-nodegroup-name-length", "ERROR", name,
	"Properties.NodegroupName",
	sprintf("NodegroupName is %d characters; EKS rejects anything longer than 63 (\"nodeGroupName can't be longer than 63 characters!\")", [count(n)]),
	"Shorten the node group name to 63 characters or fewer",
	"https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	n := resolve(name, "Properties.NodegroupName")
	_pf_ekslib_lit(n)
	count(n) > 63
}
