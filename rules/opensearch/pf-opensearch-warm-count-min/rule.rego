package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-warm-count-min", "ERROR", name,
	"Properties.ClusterConfig.WarmCount",
	sprintf("%v UltraWarm node; CreateDomain answers \"Warm storage node count must be between 2 and 150.\"", [n]),
	"Use at least 2 UltraWarm nodes",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ultrawarm.html") if {
	some name in _pf_os_domains
	n := _pf_os_num(_pf_os_opt(name, "ClusterConfig", "WarmCount"))
	n < 2
}
