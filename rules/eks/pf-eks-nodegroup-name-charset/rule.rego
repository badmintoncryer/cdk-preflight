package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-nodegroup-name-charset", "ERROR", name,
	"Properties.NodegroupName",
	sprintf("NodegroupName %v does not match ^[0-9A-Za-z][A-Za-z0-9-_]* (\"The nodegroup name parameter contains invalid characters\")", [n]),
	"Use only letters, digits, hyphens and underscores, starting with a letter or digit",
	"https://docs.aws.amazon.com/eks/latest/APIReference/API_CreateNodegroup.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	n := resolve(name, "Properties.NodegroupName")
	_pf_ekslib_lit(n)
	not regex.match(`^[0-9A-Za-z][A-Za-z0-9_-]*$`, n)
}
