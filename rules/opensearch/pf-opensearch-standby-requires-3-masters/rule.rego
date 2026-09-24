package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-standby-requires-3-masters", "ERROR", name,
	"Properties.ClusterConfig.DedicatedMasterCount",
	sprintf("standby with %v dedicated master nodes; CreateDomain answers \"Domains with standby must have 3 nodes that are eligible to be master nodes.\"", [mc]),
	"Set DedicatedMasterCount to 3, or drop MultiAZWithStandbyEnabled",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-multiaz.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "ClusterConfig", "MultiAZWithStandbyEnabled")
	mc := _pf_os_num(_pf_os_opt(name, "ClusterConfig", "DedicatedMasterCount"))
	mc != 3
}
