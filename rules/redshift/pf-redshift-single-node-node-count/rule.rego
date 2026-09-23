package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-redshift-single-node-node-count", "ERROR", name,
	"Properties.NumberOfNodes",
	sprintf("ClusterType single-node with NumberOfNodes %v; CreateCluster rejects it (\"Number of nodes must be 1 or not be supplied for cluster type single-node.\")", [n]),
	"Use NumberOfNodes 1 or omit it, or switch to ClusterType multi-node",
	"https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	_pf_redshiftlib_cluster_type(name) == "single-node"
	n := _pf_redshiftlib_num(name, "NumberOfNodes")
	n > 1
}
