package cdk_preflight

import rego.v1

# 501 is major*100+minor of Elasticsearch 5.1. Every OpenSearch version has
# encryption at rest, which is why the helper is asked for an Elasticsearch
# reading and stays undefined for anything else.

violation contains make_diag_full("pf-opensearch-encryption-at-rest-min-version", "ERROR", name,
	"Properties.EncryptionAtRestOptions.Enabled",
	sprintf("encryption at rest arrived in Elasticsearch 5.1 but the domain asks for %v; CreateDomain answers \"Encryption at rest is not supported for Elasticsearch ...\"", [v]),
	"Use Elasticsearch 5.1 or later (or any OpenSearch version), or drop EncryptionAtRestOptions",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "EncryptionAtRestOptions", "Enabled")
	v := resolve(name, "Properties.EngineVersion")
	_pf_os_engine_num(v, "Elasticsearch") < 501
}
