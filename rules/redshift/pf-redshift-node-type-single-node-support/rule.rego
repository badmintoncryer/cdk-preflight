package cdk_preflight

import rego.v1

# Node types whose cluster size starts at 2 in the management guide's node table; the
# literal is lower-cased by the lib, tokens skip.
_pf_rsnts_multi_only := {"ra3.4xlarge", "ra3.16xlarge", "rg.4xlarge", "rg.12xlarge", "dc2.8xlarge"}

violation contains make_diag_full("pf-redshift-node-type-single-node-support", "ERROR", name,
	"Properties.ClusterType",
	sprintf("ClusterType single-node on node type %s, which has no single-node configuration (minimum 2 nodes); CreateCluster rejects it", [nt]),
	"Use ClusterType multi-node with NumberOfNodes 2 or more, or a node type that has a single-node configuration (for example ra3.large or ra3.xlplus)",
	"https://docs.aws.amazon.com/redshift/latest/mgmt/working-with-clusters.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	_pf_redshiftlib_cluster_type(name) == "single-node"
	nt := _pf_redshiftlib_node_type(name)
	nt in _pf_rsnts_multi_only
}
