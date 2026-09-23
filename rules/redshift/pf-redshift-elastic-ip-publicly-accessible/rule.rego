package cdk_preflight

import rego.v1

# PubliclyAccessible defaults to false, so absent counts as not public; an unresolved
# token is not judged.
violation contains make_diag_full("pf-redshift-elastic-ip-publicly-accessible", "ERROR", name,
	"Properties.ElasticIp",
	"ElasticIp is set but PubliclyAccessible is not true; CreateCluster rejects it (\"Elastic IP address can only be specified for clusters in a publicly-accessible VPC.\")",
	"Set PubliclyAccessible: true, or drop ElasticIp",
	"https://docs.aws.amazon.com/redshift/latest/APIReference/API_CreateCluster.html") if {
	some name in resources_of_type("AWS::Redshift::Cluster")
	_pf_redshiftlib_has(name, "ElasticIp")
	_pf_redshiftlib_false_or_absent(name, "PubliclyAccessible")
}
