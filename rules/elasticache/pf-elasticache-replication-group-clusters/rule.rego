package cdk_preflight

import rego.v1

_pf_ecrgc_url := "https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/API_CreateReplicationGroup.html"

_pf_ecrgc_fix := "Give an automatic-failover group NumCacheClusters >= 2, set AutomaticFailoverEnabled: false for a single-cluster group, and never set NumCacheClusters together with NumNodeGroups"

violation contains make_diag_full("pf-elasticache-replication-group-clusters", "ERROR", name,
	"Properties.NumCacheClusters",
	sprintf("AutomaticFailoverEnabled is true but NumCacheClusters is %v; the deployment fails with \"Automatic failover requires 2 or more cache clusters. Create more cache clusters or disable automatic failover.\"", [n]),
	_pf_ecrgc_fix, _pf_ecrgc_url) if {
	some name in resources_of_type("AWS::ElastiCache::ReplicationGroup")
	resolve(name, "Properties.AutomaticFailoverEnabled") == true
	n := to_number(resolve(name, "Properties.NumCacheClusters"))
	n < 2
}

# CloudFormation's own handler turns automatic failover on unless the template
# says otherwise, so a single-cluster group without the explicit false fails
# even though the CreateReplicationGroup API accepts it (measured 2026-09-06).
violation contains make_diag_full("pf-elasticache-replication-group-clusters", "ERROR", name,
	"Properties.AutomaticFailoverEnabled",
	"NumCacheClusters is 1 and AutomaticFailoverEnabled is not set; the CloudFormation handler enables failover and the deployment fails with \"When using automatic failover, there must be at least 2 cache clusters in the replication group.\"",
	_pf_ecrgc_fix, _pf_ecrgc_url) if {
	some name in resources_of_type("AWS::ElastiCache::ReplicationGroup")
	_pf_cachelib_absent(name, "AutomaticFailoverEnabled")
	to_number(resolve(name, "Properties.NumCacheClusters")) == 1
}

violation contains make_diag_full("pf-elasticache-replication-group-clusters", "ERROR", name,
	"Properties.NumCacheClusters",
	"NumCacheClusters and NumNodeGroups are both set; the create call fails with \"NumCacheClusters can only be specified for one node group\"",
	_pf_ecrgc_fix, _pf_ecrgc_url) if {
	some name in resources_of_type("AWS::ElastiCache::ReplicationGroup")
	not _pf_cachelib_absent(name, "NumCacheClusters")
	n := to_number(resolve(name, "Properties.NumNodeGroups"))
	n > 1
}
