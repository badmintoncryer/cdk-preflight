package cdk_preflight

import rego.v1

_pf_eccmpg_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateReplicationGroup.html"

_pf_eccmpg_fix := "Point CacheParameterGroupName at a parameter group whose Properties set cluster-enabled: yes (or use a default.*.cluster.on group)"

# The parameter group usually lives in the same template, so the cluster-enabled
# parameter can be read directly; a group that is only referenced by name is left
# alone.
_pf_eccmpg_cluster_on(pgname) if {
	props := resolve(pgname, "Properties.Properties")
	is_object(props)
	lower(object.get(props, "cluster-enabled", "no")) == "yes"
}

violation contains make_diag_full("pf-elasticache-cluster-mode-parameter-group", "ERROR", name,
	"Properties.CacheParameterGroupName",
	sprintf("NumNodeGroups is %v but parameter group '%s' does not set cluster-enabled: yes; the deployment fails with \"Use a parameter group with cluster-enabled parameter to create more than one node group.\"", [n, pgname]),
	_pf_eccmpg_fix, _pf_eccmpg_url) if {
	some name in resources_of_type("AWS::ElastiCache::ReplicationGroup")
	n := to_number(resolve(name, "Properties.NumNodeGroups"))
	n > 1
	pgname := resolve(name, "Properties.CacheParameterGroupName")
	pgname in resources_of_type("AWS::ElastiCache::ParameterGroup")
	not _pf_eccmpg_cluster_on(pgname)
}
