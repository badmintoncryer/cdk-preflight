package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-encryption-key-arn", "ERROR", name,
	"Properties.DeliveryStreamEncryptionConfigurationInput.KeyARN",
	"KeyType is CUSTOMER_MANAGED_CMK but KeyARN is not set; the stream create fails with \"KeyARN has to be specified when KeyType is CUSTOMER_MANAGED_CMK\"",
	"Set KeyARN, or switch KeyType to AWS_OWNED_CMK",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_DeliveryStreamEncryptionConfigurationInput.html") if {
	some name in resources_of_type("AWS::KinesisFirehose::DeliveryStream")
	e := object.get(_pf_fhlib_props(name), "DeliveryStreamEncryptionConfigurationInput", null)
	is_object(e)
	object.get(e, "KeyType", null) == "CUSTOMER_MANAGED_CMK"
	object.get(e, "KeyARN", "__pf_absent") == "__pf_absent"
}
