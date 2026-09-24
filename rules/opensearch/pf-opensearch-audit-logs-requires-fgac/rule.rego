package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-audit-logs-requires-fgac", "ERROR", name,
	"Properties.LogPublishingOptions.AUDIT_LOGS",
	"AUDIT_LOGS publishing needs fine-grained access control; without it CreateDomain answers \"audit log publishing cannot be enabled as you do not have advanced security options configured\"",
	"Set AdvancedSecurityOptions.Enabled to true (with encryption at rest, node-to-node encryption and EnforceHTTPS), or drop the AUDIT_LOGS entry",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/audit-logs.html") if {
	some name in _pf_os_domains
	_pf_os_on3(name, "LogPublishingOptions", "AUDIT_LOGS", "Enabled")
	not _pf_os_on(name, "AdvancedSecurityOptions", "Enabled")
}
