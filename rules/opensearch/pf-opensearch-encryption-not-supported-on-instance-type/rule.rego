package cdk_preflight

import rego.v1

# Denylist: the only OpenSearch_2.19 types answering EncryptionEnabled false
# are t2.small / t2.medium and the five r3 sizes (list-instance-type-details,
# us-east-1 2026-09-25), which is both families whole.
_pf_osenc_no_encryption := {"t2", "r3"}

violation contains make_diag_full("pf-opensearch-encryption-not-supported-on-instance-type", "ERROR", name,
	"Properties.EncryptionAtRestOptions.Enabled",
	sprintf("%v cannot encrypt at rest; CreateDomain answers \"Encryption at rest is not supported with %v instances\"", [t, t]),
	"Pick a family that supports encryption at rest (t3 / m6g / r6g and newer), or drop EncryptionAtRestOptions",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/encryption-at-rest.html") if {
	some name in _pf_os_domains
	_pf_os_on(name, "EncryptionAtRestOptions", "Enabled")
	t := _pf_os_opt(name, "ClusterConfig", "InstanceType")
	_pf_os_family(t) in _pf_osenc_no_encryption
}
