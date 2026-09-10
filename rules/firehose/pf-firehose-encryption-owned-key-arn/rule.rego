package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-encryption-owned-key-arn", "ERROR", name,
	"Properties.DeliveryStreamEncryptionConfigurationInput.KeyARN",
	"KeyType is AWS_OWNED_CMK but a KeyARN is set; the stream create fails with \"KeyARN cannot be specified when KeyType is AWS_OWNED_CMK\"",
	"Drop KeyARN, or switch KeyType to CUSTOMER_MANAGED_CMK",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_DeliveryStreamEncryptionConfigurationInput.html") if {
	some name in resources_of_type("AWS::KinesisFirehose::DeliveryStream")
	e := object.get(_pf_fhlib_props(name), "DeliveryStreamEncryptionConfigurationInput", null)
	is_object(e)
	object.get(e, "KeyType", null) == "AWS_OWNED_CMK"
	object.get(e, "KeyARN", "__pf_absent") != "__pf_absent"
}
