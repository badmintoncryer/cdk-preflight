package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-warm-options-require-enabled", "ERROR", name,
	sprintf("Properties.ClusterConfig.%v", [k]),
	sprintf("%v is set while WarmEnabled is not true; CreateDomain answers \"WarmEnabled must be set to true to specify WarmCount and WarmType.\"", [k]),
	"Set ClusterConfig.WarmEnabled to true (with dedicated master nodes), or drop the UltraWarm options",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-clusterconfig.html") if {
	some name in _pf_os_domains
	some k in {"WarmCount", "WarmType"}
	_pf_os_has2(name, "ClusterConfig", k)
	not _pf_os_on(name, "ClusterConfig", "WarmEnabled")
}
