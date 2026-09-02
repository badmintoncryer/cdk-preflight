package cdk_preflight

import rego.v1

# Both directions deploy-verified: none set, and two set. Key presence is
# read from the preprocessed document (see AGENTS.md).
_pf_fhod_dests := {
	"S3DestinationConfiguration",
	"ExtendedS3DestinationConfiguration",
	"RedshiftDestinationConfiguration",
	"ElasticsearchDestinationConfiguration",
	"AmazonopensearchserviceDestinationConfiguration",
	"AmazonOpenSearchServerlessDestinationConfiguration",
	"SplunkDestinationConfiguration",
	"HttpEndpointDestinationConfiguration",
	"SnowflakeDestinationConfiguration",
	"IcebergDestinationConfiguration",
}

violation contains make_diag_full("pf-firehose-one-destination", "ERROR", name,
	"Properties",
	sprintf("%d destination configurations are set; the stream create fails with \"Exactly one destination configuration is supported for a Firehose\"", [n]),
	"Set exactly one *DestinationConfiguration",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kinesisfirehose-deliverystream.html") if {
	some name in resources_of_type("AWS::KinesisFirehose::DeliveryStream")
	props := input.resources[name].properties
	is_object(props)
	n := count([k | some k in _pf_fhod_dests; object.get(props, k, "__pf_absent") != "__pf_absent"])
	n != 1
}
