package cdk_preflight

import rego.v1

# S3 and CloudWatch take SSE-KMS, job bookmarks take CSE-KMS; each one refuses to
# be created without a key. The other modes (SSE-S3, DISABLED) take no key.
_pf_gluesec_single := {
	"CloudWatchEncryption": ["CloudWatchEncryptionMode", "SSE-KMS"],
	"JobBookmarksEncryption": ["JobBookmarksEncryptionMode", "CSE-KMS"],
}

violation contains make_diag_full("pf-glue-security-configuration-kms-key", "ERROR", name,
	sprintf("Properties.EncryptionConfiguration.S3Encryptions.%d.KmsKeyArn", [i]),
	"An S3Encryptions entry asks for SSE-KMS with no KmsKeyArn; CreateSecurityConfiguration fails with \"kmsKeyArn can not be empty for s3EncryptionMode SSE_KMS\"",
	"Set KmsKeyArn to a KMS key in the same region, or use SSE-S3",
	"https://docs.aws.amazon.com/glue/latest/dg/encryption-security-configuration.html") if {
	some name in resources_of_type("AWS::Glue::SecurityConfiguration")
	arr := object.get(_pf_gluelib_encryption(name), "S3Encryptions", [])
	is_array(arr)
	some i, e in arr
	is_object(e)
	e.S3EncryptionMode == "SSE-KMS"
	object.get(e, "KmsKeyArn", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-glue-security-configuration-kms-key", "ERROR", name,
	sprintf("Properties.EncryptionConfiguration.%s.KmsKeyArn", [k]),
	sprintf("%s asks for %s with no KmsKeyArn; CreateSecurityConfiguration refuses the empty kmsKeyArn", [k, spec[1]]),
	"Set KmsKeyArn to a KMS key in the same region, or turn the mode off",
	"https://docs.aws.amazon.com/glue/latest/dg/encryption-security-configuration.html") if {
	some name in resources_of_type("AWS::Glue::SecurityConfiguration")
	some k, spec in _pf_gluesec_single
	e := object.get(_pf_gluelib_encryption(name), k, {})
	is_object(e)
	e[spec[0]] == spec[1]
	object.get(e, "KmsKeyArn", "__pf_absent") == "__pf_absent"
}
