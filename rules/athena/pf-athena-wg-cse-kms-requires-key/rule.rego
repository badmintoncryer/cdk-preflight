package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-athena-wg-cse-kms-requires-key", "ERROR", name,
	"Properties.WorkGroupConfiguration.ResultConfiguration.EncryptionConfiguration.KmsKey",
	"EncryptionOption is CSE_KMS but no KmsKey is set; CreateWorkGroup fails with \"KMS Customer Master Key ID is null or empty\"",
	"Set EncryptionConfiguration.KmsKey, or use EncryptionOption SSE_S3, which needs no key",
	"https://docs.aws.amazon.com/athena/latest/APIReference/API_EncryptionConfiguration.html") if {
	some name in resources_of_type("AWS::Athena::WorkGroup")
	enc := _pf_athlib_obj(_pf_athlib_resultcfg(name), "EncryptionConfiguration")
	object.get(enc, "EncryptionOption", "") == "CSE_KMS"
	not _pf_athlib_has(enc, "KmsKey")
}
