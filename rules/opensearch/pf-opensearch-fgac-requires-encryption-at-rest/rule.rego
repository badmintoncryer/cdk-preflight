package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-fgac-requires-encryption-at-rest", "ERROR", name,
	"Properties.EncryptionAtRestOptions.Enabled",
	"fine-grained access control is on but encryption at rest is not; CreateDomain answers \"You must enable encryption at rest to use advanced security options.\"",
	"Set EncryptionAtRestOptions.Enabled to true",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/fgac.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "AdvancedSecurityOptions", "Enabled")
	not _pf_os_on(name, "EncryptionAtRestOptions", "Enabled")
}
