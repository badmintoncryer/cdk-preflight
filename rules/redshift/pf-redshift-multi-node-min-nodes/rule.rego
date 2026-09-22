package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-redshift-multi-node-min-nodes", "ERROR", name,
	"Properties.NumberOfNodes",
	sprintf("ClusterType multi-node with NumberOfNodes %v; CreateCluster rejects it (\"Number of nodes for cluster type multi-node must be greater than or equal to 2.\")", [n]),
	"Use NumberOfNodes 2 or more, or ClusterType single-node",
	"https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	_pf_redshiftlib_cluster_type(name) == "multi-node"
	n := _pf_redshiftlib_num(name, "NumberOfNodes")
	n < 2
}
