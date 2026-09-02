package cdk_preflight

import rego.v1

# The schema floor is 1; the 64 floor only applies with dynamic
# partitioning on - a conditional bound no schema layer can express.
violation contains make_diag_full("pf-firehose-dynamic-partitioning-buffer", "ERROR", name,
	"Properties.ExtendedS3DestinationConfiguration.BufferingHints.SizeInMBs",
	sprintf("SizeInMBs %v with dynamic partitioning; the stream create fails with \"BufferingHints.SizeInMBs must be at least 64 when Dynamic Partitioning is enabled.\"", [s]),
	"Raise SizeInMBs to at least 64",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-kinesisfirehose-deliverystream-dynamicpartitioningconfiguration.html") if {
	some name in resources_of_type("AWS::KinesisFirehose::DeliveryStream")
	coerce_to_bool(resolve(name, "Properties.ExtendedS3DestinationConfiguration.DynamicPartitioningConfiguration.Enabled")) == true
	s := to_number(resolve(name, "Properties.ExtendedS3DestinationConfiguration.BufferingHints.SizeInMBs"))
	s < 64
}
