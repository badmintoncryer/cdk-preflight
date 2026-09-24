package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-opensearch-or1-requires-encryption-at-rest", "ERROR", name,
	"Properties.EncryptionAtRestOptions.Enabled",
	sprintf("%v stores its data in S3, so CreateDomain answers \"Enable encryption at rest to use the OR1 instance family\"", [t]),
	"Set EncryptionAtRestOptions.Enabled to true, or pick a non-OR1 family",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/or1.html") if {
	some name in _pf_os_domains
	t := _pf_os_opt(name, "ClusterConfig", "InstanceType")
	_pf_os_family(t) == "or1"
	not _pf_os_on(name, "EncryptionAtRestOptions", "Enabled")
}
