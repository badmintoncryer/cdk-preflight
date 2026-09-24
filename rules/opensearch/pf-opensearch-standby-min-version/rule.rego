package cdk_preflight

import rego.v1

# 103 is major*100+minor of OpenSearch 1.3. Elasticsearch never had standby at
# all, so an ES version is left to the service rather than answered here.

violation contains make_diag_full("pf-opensearch-standby-min-version", "ERROR", name,
	"Properties.ClusterConfig.MultiAZWithStandbyEnabled",
	sprintf("standby arrived in OpenSearch 1.3 but the domain asks for %v; CreateDomain answers \"Domains with standby are only supported for OpenSearch version 1.3 and later.\"", [v]),
	"Use OpenSearch 1.3 or later, or drop MultiAZWithStandbyEnabled",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/managedomains-multiaz.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "ClusterConfig", "MultiAZWithStandbyEnabled")
	v := resolve(name, "Properties.EngineVersion")
	_pf_os_engine_num(v, "OpenSearch") < 103
}
