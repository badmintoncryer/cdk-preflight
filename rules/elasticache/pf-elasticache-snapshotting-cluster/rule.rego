package cdk_preflight

import rego.v1

_pf_ecsc_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateReplicationGroup.html"

_pf_ecsc_fix := "Drop SnapshottingClusterId when the group has more than one node group — cluster mode enabled groups snapshot every shard"

violation contains make_diag_full("pf-elasticache-snapshotting-cluster", "ERROR", name,
	"Properties.SnapshottingClusterId",
	"SnapshottingClusterId is set on a cluster mode enabled replication group (NumNodeGroups > 1); the deployment fails with \"Cannot set snapshotting cluster for cluster mode enabled replication group.\"",
	_pf_ecsc_fix, _pf_ecsc_url) if {
	some name in resources_of_type("AWS::ElastiCache::ReplicationGroup")
	not _pf_cachelib_absent(name, "SnapshottingClusterId")
	n := to_number(resolve(name, "Properties.NumNodeGroups"))
	n > 1
}
