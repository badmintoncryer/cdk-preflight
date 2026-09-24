package cdk_preflight

import rego.v1

# 600 is major*100+minor of Elasticsearch 6.0. Node-to-node encryption is on
# every OpenSearch version, so the helper is asked for an Elasticsearch
# reading and stays undefined for anything else.

violation contains make_diag_full("pf-opensearch-node-to-node-min-version", "ERROR", name,
	"Properties.NodeToNodeEncryptionOptions.Enabled",
	sprintf("node-to-node encryption arrived in Elasticsearch 6.0 but the domain asks for %v; CreateDomain answers \"Node to Node Encryption feature is not available for the selected ES Version\"", [v]),
	"Use Elasticsearch 6.0 or later (or any OpenSearch version), or drop NodeToNodeEncryptionOptions",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/ntn.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "NodeToNodeEncryptionOptions", "Enabled")
	v := resolve(name, "Properties.EngineVersion")
	_pf_os_engine_num(v, "Elasticsearch") < 600
}
