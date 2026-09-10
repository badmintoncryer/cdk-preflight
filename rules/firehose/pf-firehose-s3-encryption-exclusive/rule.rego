package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-s3-encryption-exclusive", "ERROR", name,
	sprintf("%s.EncryptionConfiguration", [path]),
	sprintf("%d of NoEncryptionConfig / KMSEncryptionConfig are set; the stream create fails with \"Exactly one of NoEncryptionConfig or KMSEncryptionConfig must be specified\"", [n]),
	"Set exactly one of NoEncryptionConfig or KMSEncryptionConfig, or drop EncryptionConfiguration",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_EncryptionConfiguration.html") if {
	some [name, path, c] in _pf_fhlib_prefixed
	e := object.get(c, "EncryptionConfiguration", null)
	is_object(e)
	n := count([k | some k in {"NoEncryptionConfig", "KMSEncryptionConfig"}; object.get(e, k, "__pf_absent") != "__pf_absent"])
	n != 1
}
