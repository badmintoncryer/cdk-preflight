package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-msk-source-config", "ERROR", name,
	"Properties.MSKSourceConfiguration",
	"DeliveryStreamType is MSKAsSource but MSKSourceConfiguration is not set; the stream create fails with \"MSKSourceConfig is mandatory for MSK as Source stream type.\"",
	"Add MSKSourceConfiguration (cluster ARN, topic, authentication)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kinesisfirehose-deliverystream.html") if {
	some name in resources_of_type("AWS::KinesisFirehose::DeliveryStream")
	p := _pf_fhlib_props(name)
	object.get(p, "DeliveryStreamType", null) == "MSKAsSource"
	object.get(p, "MSKSourceConfiguration", "__pf_absent") == "__pf_absent"
}
