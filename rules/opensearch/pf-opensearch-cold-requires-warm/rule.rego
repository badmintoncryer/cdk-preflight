package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-cold-requires-warm", "ERROR", name,
	"Properties.ClusterConfig.ColdStorageOptions.Enabled",
	"cold storage is enabled without UltraWarm; CreateDomain answers \"To use cold storage, you must have UltraWarm enabled.\"",
	"Set ClusterConfig.WarmEnabled to true with a WarmType and WarmCount, or drop ColdStorageOptions",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-coldstorageoptions.html") if {
	some name in _pf_os_domains
	_pf_os_on3(name, "ClusterConfig", "ColdStorageOptions", "Enabled")
	not _pf_os_on(name, "ClusterConfig", "WarmEnabled")
}
