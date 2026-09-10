package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-encryption-kinesis-source", "ERROR", name,
	"Properties.DeliveryStreamEncryptionConfigurationInput",
	sprintf("a %s stream cannot enable server-side encryption; the stream create fails with \"Server side encryption from firehose is only allowed for direct put delivery streams and database as a source delivery streams\"", [t]),
	"Encrypt the source Kinesis stream instead, or drop DeliveryStreamEncryptionConfigurationInput",
	"https://docs.aws.amazon.com/firehose/latest/APIReference/API_DeliveryStreamEncryptionConfigurationInput.html") if {
	some name in resources_of_type("AWS::KinesisFirehose::DeliveryStream")
	p := _pf_fhlib_props(name)
	object.get(p, "DeliveryStreamEncryptionConfigurationInput", "__pf_absent") != "__pf_absent"
	t := object.get(p, "DeliveryStreamType", null)
	t in {"KinesisStreamAsSource", "MSKAsSource"}
}
