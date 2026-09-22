package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-redshift-elastic-ip-vs-az-relocation", "ERROR", name,
	"Properties.ElasticIp",
	"ElasticIp is set on a cluster with AvailabilityZoneRelocation enabled; CreateCluster rejects the pair (\"Don't specify the Elastic IP address for a publicly accessible cluster with availability zone relocation turned on.\")",
	"Drop ElasticIp, or set AvailabilityZoneRelocation: false",
	"https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	_pf_redshiftlib_has(name, "ElasticIp")
	_pf_redshiftlib_true(name, "AvailabilityZoneRelocation")
}
