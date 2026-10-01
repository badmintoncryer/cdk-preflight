package cdk_preflight

import rego.v1

# us-gov-* は RegionList の pattern で同梱エンジンが止める（F3031）ので cn-* だけ見る
violation contains make_diag_full("pf-cassandra-keyspace-multiregion-partition", "ERROR", name, sprintf("Properties.ReplicationSpecification.RegionList.%d", [i]),
	sprintf("RegionList contains %v; multi-Region replication is not available in the China Regions and Keyspaces answers \"Replication regions must be among the following regions\"", [r]),
	"Replicate only between commercial AWS Regions",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/multiRegion-replication_usage-notes.html") if {
	some name in resources_of_type("AWS::Cassandra::Keyspace")
	_pf_cass_mr(name)
	rl := input.resources[name].properties.ReplicationSpecification.RegionList
	is_array(rl)
	some i, r in rl
	is_string(r)
	startswith(r, "cn-")
}
