package cdk_preflight

import rego.v1

_pf_kinenc_url := "https://docs.aws.amazon.com/managed-flink/latest/apiv2/API_ApplicationEncryptionConfiguration.html"

_pf_kinenc_cfg(name) := enc if {
	enc := _pf_kinlib_obj(_pf_kinlib_appcfg(name), "ApplicationEncryptionConfiguration")
}

violation contains make_diag_full("pf-kinesisanalytics-encryption-key-type", "ERROR", name,
	"Properties.ApplicationConfiguration.ApplicationEncryptionConfiguration.KeyId",
	"KeyType is AWS_OWNED_KEY but KeyId is set; CreateApplication fails with \"keyId cannot be provided with the AWS_OWNED_KEY keyType.\"",
	"Drop KeyId, or switch KeyType to CUSTOMER_MANAGED_KEY",
	_pf_kinenc_url) if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	enc := _pf_kinenc_cfg(name)
	object.get(enc, "KeyType", "") == "AWS_OWNED_KEY"
	_pf_kinlib_has(enc, "KeyId")
}

violation contains make_diag_full("pf-kinesisanalytics-encryption-key-type", "ERROR", name,
	"Properties.ApplicationConfiguration.ApplicationEncryptionConfiguration.KeyId",
	"KeyType is CUSTOMER_MANAGED_KEY but no KeyId is given; CreateApplication fails with \"You have selected CUSTOMER_MANAGED_KEY for keyType. Please provide a valid key id.\"",
	"Set KeyId to the customer managed key, or switch KeyType to AWS_OWNED_KEY",
	_pf_kinenc_url) if {
	some name in resources_of_type("AWS::KinesisAnalyticsV2::Application")
	enc := _pf_kinenc_cfg(name)
	object.get(enc, "KeyType", "") == "CUSTOMER_MANAGED_KEY"
	not _pf_kinlib_has(enc, "KeyId")
}
