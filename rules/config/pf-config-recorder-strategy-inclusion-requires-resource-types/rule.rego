package cdk_preflight

import rego.v1

_pf_cfgsir_err := "the recorder create fails: an inclusion strategy with nothing included records nothing"

violation contains make_diag_full("pf-config-recorder-strategy-inclusion-requires-resource-types", "ERROR", name,
	"Properties.RecordingGroup.ResourceTypes",
	sprintf("RecordingStrategy.UseOnly is INCLUSION_BY_RESOURCE_TYPES but ResourceTypes is empty; %s", [_pf_cfgsir_err]),
	"List the resource types to record in RecordingGroup.ResourceTypes",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-config-configurationrecorder-recordingstrategy.html") if {
	some name in resources_of_type("AWS::Config::ConfigurationRecorder")
	_pf_cfglib_uses_only(name, "INCLUSION_BY_RESOURCE_TYPES")
	count(_pf_cfglib_group_resource_types(name)) == 0
}
