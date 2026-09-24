package cdk_preflight

import rego.v1

# 607 is major*100+minor of Elasticsearch 6.7. Fine-grained access control is
# on every OpenSearch version, so the helper is asked for an Elasticsearch
# reading and stays undefined for anything else.

violation contains make_diag_full("pf-opensearch-fgac-min-version", "ERROR", name,
	"Properties.AdvancedSecurityOptions.Enabled",
	sprintf("fine-grained access control arrived in Elasticsearch 6.7 but the domain asks for %v; CreateDomain answers \"Advanced security feature is not available for the selected ES Version.\"", [v]),
	"Use Elasticsearch 6.7 or later (or any OpenSearch version), or drop AdvancedSecurityOptions",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/fgac.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "AdvancedSecurityOptions", "Enabled")
	v := resolve(name, "Properties.EngineVersion")
	_pf_os_engine_num(v, "Elasticsearch") < 607
}
