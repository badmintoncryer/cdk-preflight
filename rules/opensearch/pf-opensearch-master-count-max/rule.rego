package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-master-count-max", "ERROR", name,
	"Properties.ClusterConfig.DedicatedMasterCount",
	sprintf("%v dedicated master nodes; CreateDomain answers \"Dedicated master instances count should be between 2 and 5.\"", [n]),
	"Use 3 or 5 dedicated master nodes (the service takes 2 to 5)",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-dedicatedmasternodes.html") if {
	some name in _pf_os_domains
	n := _pf_os_num(_pf_os_opt(name, "ClusterConfig", "DedicatedMasterCount"))
	n > 5
}
