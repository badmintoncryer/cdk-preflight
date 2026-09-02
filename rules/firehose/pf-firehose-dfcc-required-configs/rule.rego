package cdk_preflight

import rego.v1

# The three sub-configurations are unconditionally required once Enabled
# is true; the service rejects each absence in turn. Read from the
# preprocessed document (see AGENTS.md).
_pf_fhdfcc_outer(name) := c if {
	props := input.resources[name].properties
	is_object(props)
	c := object.get(props, "ExtendedS3DestinationConfiguration", {})
	is_object(c)
}

_pf_fhdfcc_conf(name) := c if {
	x := _pf_fhdfcc_outer(name)
	c := object.get(x, "DataFormatConversionConfiguration", {})
	is_object(c)
}

violation contains make_diag_full("pf-firehose-dfcc-required-configs", "ERROR", name,
	sprintf("Properties.ExtendedS3DestinationConfiguration.DataFormatConversionConfiguration.%s", [k]),
	sprintf("Data format conversion is enabled without %s; the stream create fails with \"%s must not be null\"", [k, k]),
	"Set InputFormatConfiguration, OutputFormatConfiguration, and SchemaConfiguration together",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-kinesisfirehose-deliverystream-dataformatconversionconfiguration.html") if {
	some name in resources_of_type("AWS::KinesisFirehose::DeliveryStream")
	c := _pf_fhdfcc_conf(name)
	coerce_to_bool(object.get(c, "Enabled", false)) == true
	some k in {"InputFormatConfiguration", "OutputFormatConfiguration", "SchemaConfiguration"}
	object.get(c, k, "__pf_absent") == "__pf_absent"
}
