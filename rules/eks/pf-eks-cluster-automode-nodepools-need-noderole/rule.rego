package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-cluster-automode-nodepools-need-noderole", "ERROR", name,
	"Properties.ComputeConfig.NodeRoleArn",
	"ComputeConfig lists node pools but no NodeRoleArn (\"When Compute Config nodeRoleArn is null or empty, nodePool list cannot be populated.\")",
	"Give ComputeConfig a NodeRoleArn, or drop NodePools",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-cluster-computeconfig.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	is_array(object.get(_pf_ekslib_props(name), ["ComputeConfig", "NodePools"], null))
	flatten_list(name, "Properties.ComputeConfig.NodePools") != []
	not _pf_ekslib_ohas(_pf_ekslib_get(name, "ComputeConfig"), "NodeRoleArn")
}
