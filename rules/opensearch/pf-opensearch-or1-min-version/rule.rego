package cdk_preflight

import rego.v1

# 211 is major*100+minor of OpenSearch 2.11, not to_number("2.11") - read as a
# decimal, 2.9 would outrank it and the rule would go quiet on the one version
# that matters. Elasticsearch never offered OR1, so asking the helper for an
# OpenSearch reading leaves ES versions undefined rather than flagged.

violation contains make_diag_full("pf-opensearch-or1-min-version", "ERROR", name,
	"Properties.ClusterConfig.InstanceType",
	sprintf("the OR1 family arrived in OpenSearch 2.11 but the domain asks for %v; CreateDomain answers \"Invalid instance type: %v\"", [v, t]),
	"Use OpenSearch 2.11 or later, or pick a family the chosen version offers",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/or1.html") if {
	some name in _pf_os_domains
	t := _pf_os_opt(name, "ClusterConfig", "InstanceType")
	_pf_os_family(t) == "or1"
	v := resolve(name, "Properties.EngineVersion")
	_pf_os_engine_num(v, "OpenSearch") < 211
}
