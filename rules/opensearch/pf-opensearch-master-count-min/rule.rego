package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-master-count-min", "ERROR", name,
	"Properties.ClusterConfig.DedicatedMasterCount",
	sprintf("%v dedicated master node; CreateDomain answers \"Dedicated master node count should be greater than 1.\"", [n]),
	"Use 3 dedicated master nodes (the service takes 2 to 5, and an even count risks a split brain)",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-dedicatedmasternodes.html") if {
	some name in _pf_os_domains
	n := _pf_os_num(_pf_os_opt(name, "ClusterConfig", "DedicatedMasterCount"))
	n < 2
}
