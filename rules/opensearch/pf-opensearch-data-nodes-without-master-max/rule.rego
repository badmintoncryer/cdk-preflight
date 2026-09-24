package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-data-nodes-without-master-max", "ERROR", name,
	"Properties.ClusterConfig.InstanceCount",
	sprintf("%v data nodes without dedicated masters; CreateDomain answers \"Dedicated master instances must be enabled for domains with more than 10 instance count.\"", [n]),
	"Set DedicatedMasterEnabled with a DedicatedMasterType and DedicatedMasterCount, or keep the data nodes at 10 or fewer",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/limits.html") if {
	some name in _pf_os_domains
	n := _pf_os_num(_pf_os_opt(name, "ClusterConfig", "InstanceCount"))
	n > 10
	not _pf_os_on(name, "ClusterConfig", "DedicatedMasterEnabled")
}
