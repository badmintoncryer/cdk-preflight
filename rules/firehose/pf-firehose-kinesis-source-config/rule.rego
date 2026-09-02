package cdk_preflight

import rego.v1

# Only this direction is a deploy failure - DirectPut with a (silently
# ignored) source configuration deploys fine (bench f06). Absence is
# proven against the preprocessed document (see AGENTS.md).
_pf_fhksc_missing(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "KinesisStreamSourceConfiguration", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-firehose-kinesis-source-config", "ERROR", name,
	"Properties.KinesisStreamSourceConfiguration",
	"DeliveryStreamType is KinesisStreamAsSource but no source configuration is set; the stream create fails with \"KinesisSourceStreamConfig is mandatory for KinesisStreamAsSource stream type.\"",
	"Add KinesisStreamSourceConfiguration with the stream ARN and role",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-kinesisfirehose-deliverystream.html") if {
	some name in resources_of_type("AWS::KinesisFirehose::DeliveryStream")
	resolve(name, "Properties.DeliveryStreamType") == "KinesisStreamAsSource"
	_pf_fhksc_missing(name)
}
