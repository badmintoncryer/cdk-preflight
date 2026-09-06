package cdk_preflight

import rego.v1

_pf_ecugt_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateReplicationGroup.html"

_pf_ecugt_fix := "Set TransitEncryptionEnabled: true on a replication group that uses UserGroupIds"

violation contains make_diag_full("pf-elasticache-user-group-transit-encryption", "ERROR", name,
	"Properties.UserGroupIds",
	"UserGroupIds is set but TransitEncryptionEnabled is not true; the create call fails with \"User group based access control requires encryption-in-transit to be enabled on the replication group.\"",
	_pf_ecugt_fix, _pf_ecugt_url) if {
	some name in resources_of_type("AWS::ElastiCache::ReplicationGroup")
	groups := resolve(name, "Properties.UserGroupIds")
	is_array(groups)
	count(groups) > 0
	not _pf_ecugt_transit(name)
}

_pf_ecugt_transit(name) if resolve(name, "Properties.TransitEncryptionEnabled") == true
