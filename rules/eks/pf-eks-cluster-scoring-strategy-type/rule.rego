package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-eks-cluster-scoring-strategy-type", "ERROR", name,
	"Properties.KubeSchedulerConfig.NodeResourcesFit.ScoringStrategy.Type",
	sprintf("ScoringStrategy.Type %s is not supported; CreateCluster fails with \"kubeSchedulerConfig.nodeResourcesFit.scoringStrategy.type '%s' is not supported. Allowed values: [LeastAllocated, MostAllocated].\"", [t, t]),
	"Use LeastAllocated or MostAllocated",
	"https://docs.aws.amazon.com/eks/latest/userguide/control-plane-parameters.html") if {
	some name in resources_of_type("AWS::EKS::Cluster")
	ks := _pf_ekslib_get(name, "KubeSchedulerConfig")
	nrf := _pf_ekslib_oget(ks, "NodeResourcesFit")
	ss := _pf_ekslib_oget(nrf, "ScoringStrategy")
	t := _pf_ekslib_oget(ss, "Type")
	_pf_ekslib_lit(t)
	not t in {"LeastAllocated", "MostAllocated"}
}
