package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-redshift-cluster-version-1-0", "ERROR", name,
	"Properties.ClusterVersion",
	sprintf("ClusterVersion '%s' does not exist; only 1.0 is available and CreateCluster rejects it (\"Cannot find Cluster version %s\")", [cv, cv]),
	"Set ClusterVersion to \"1.0\" or omit it",
	"https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	cv := _pf_redshiftlib_str(name, "ClusterVersion")
	cv != "1.0"
}
