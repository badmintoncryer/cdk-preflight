package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-fgac-requires-node-to-node", "ERROR", name,
	"Properties.NodeToNodeEncryptionOptions.Enabled",
	"fine-grained access control is on but node-to-node encryption is not; CreateDomain answers \"You must enable node-to-node encryption to use advanced security options.\"",
	"Set NodeToNodeEncryptionOptions.Enabled to true",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/fgac.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "AdvancedSecurityOptions", "Enabled")
	not _pf_os_on(name, "NodeToNodeEncryptionOptions", "Enabled")
}
