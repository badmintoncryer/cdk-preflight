package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-warm-requires-master", "ERROR", name,
	"Properties.ClusterConfig.WarmEnabled",
	"UltraWarm without dedicated masters; CreateDomain answers \"To use warm storage, your domain must have dedicated master nodes.\"",
	"Set DedicatedMasterEnabled with a DedicatedMasterType and DedicatedMasterCount, or drop the UltraWarm options",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ultrawarm.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "ClusterConfig", "WarmEnabled")
	not _pf_os_on(name, "ClusterConfig", "DedicatedMasterEnabled")
}
