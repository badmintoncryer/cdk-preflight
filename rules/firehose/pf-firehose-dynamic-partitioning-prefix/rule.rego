package cdk_preflight

import rego.v1

# Partitioned delivery has nowhere to put the keys unless the prefix
# interpolates them via !{partitionKeyFrom...} namespaces.
violation contains make_diag_full("pf-firehose-dynamic-partitioning-prefix", "ERROR", name,
	"Properties.ExtendedS3DestinationConfiguration.Prefix",
	sprintf("Prefix '%s' has no partition namespace; the stream create fails with \"S3 Prefix should contain Dynamic Partitioning namespaces when Dynamic Partitioning is enabled\"", [p]),
	"Interpolate at least one !{partitionKeyFromQuery:...} or !{partitionKeyFromLambda:...} into the prefix",
	"https://docs.aws.amazon.com/firehose/latest/dev/dynamic-partitioning.html") if {
	some name in resources_of_type("AWS::KinesisFirehose::DeliveryStream")
	coerce_to_bool(resolve(name, "Properties.ExtendedS3DestinationConfiguration.DynamicPartitioningConfiguration.Enabled")) == true
	p := resolve(name, "Properties.ExtendedS3DestinationConfiguration.Prefix")
	is_string(p)
	not contains(p, "!{partitionKey")
}
