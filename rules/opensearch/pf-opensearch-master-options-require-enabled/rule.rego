package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-master-options-require-enabled", "ERROR", name,
	sprintf("Properties.ClusterConfig.%v", [k]),
	sprintf("%v is set while DedicatedMasterEnabled is not true; CreateDomain answers \"DedicatedMasterEnabled must be set to True to specify the DedicatedMasterCount and DedicatedMasterType options.\"", [k]),
	"Set ClusterConfig.DedicatedMasterEnabled to true, or drop the dedicated master options",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-opensearchservice-domain-clusterconfig.html") if {
	some name in _pf_os_domains
	some k in {"DedicatedMasterCount", "DedicatedMasterType"}
	_pf_os_has2(name, "ClusterConfig", k)
	not _pf_os_on(name, "ClusterConfig", "DedicatedMasterEnabled")
}
