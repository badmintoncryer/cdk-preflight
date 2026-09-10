package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-firehose-database-source-config", "ERROR", name,
	"Properties.IcebergDestinationConfiguration",
	"DeliveryStreamType is DatabaseAsSource but the destination is not Iceberg; the stream create fails with \"IcebergDestinationConfiguration must be specified for Database as Source.\"",
	"Deliver change data capture streams to an Apache Iceberg destination",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kinesisfirehose-deliverystream.html") if {
	some name in resources_of_type("AWS::KinesisFirehose::DeliveryStream")
	p := _pf_fhlib_props(name)
	object.get(p, "DeliveryStreamType", null) == "DatabaseAsSource"
	object.get(p, "IcebergDestinationConfiguration", "__pf_absent") == "__pf_absent"
}
