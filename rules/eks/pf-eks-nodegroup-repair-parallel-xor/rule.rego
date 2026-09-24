package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-nodegroup-repair-parallel-xor", "ERROR", name,
	"Properties.NodeRepairConfig",
	"NodeRepairConfig sets both MaxParallelNodesRepairedCount and MaxParallelNodesRepairedPercentage (\"Either provide max parallel nodes to repair count or percentage in the request.\")",
	"Keep one of MaxParallelNodesRepairedCount or MaxParallelNodesRepairedPercentage",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-eks-nodegroup-noderepairconfig.html") if {
	some name in resources_of_type("AWS::EKS::Nodegroup")
	nrc := _pf_ekslib_get(name, "NodeRepairConfig")
	_pf_ekslib_ohas(nrc, "MaxParallelNodesRepairedCount")
	_pf_ekslib_ohas(nrc, "MaxParallelNodesRepairedPercentage")
}
