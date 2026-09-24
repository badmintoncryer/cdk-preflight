package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aoss-encryption-policy-kms-arn-required", "ERROR", name,
	"Properties.Policy.KmsARN",
	"the encryption policy sets AWSOwnedKey to false but names no KmsARN; CreateSecurityPolicy answers \"Policy json is invalid, error: [$.AWSOwnedKey: must be a constant value true]\"",
	"Add KmsARN with a customer managed key, or set AWSOwnedKey to true",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-encryption.html") if {
	some name in _pf_aoss_enc
	d := _pf_aoss_doc(name)
	is_object(d)
	object.get(d, "AWSOwnedKey", null) == false
	object.get(d, "KmsARN", "__pf_absent") == "__pf_absent"
}
