package cdk_preflight

import rego.v1

_pf_cfgast_err := "the recorder create fails: AllSupported records every supported type and cannot be narrowed"

violation contains make_diag_full("pf-config-recorder-all-supported-with-resource-types", "ERROR", name,
	"Properties.RecordingGroup.ResourceTypes",
	sprintf("RecordingGroup lists %d resource type(s) while AllSupported is true; %s", [count(types), _pf_cfgast_err]),
	"Drop ResourceTypes, or set AllSupported to false",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-config-configurationrecorder-recordinggroup.html") if {
	some name in resources_of_type("AWS::Config::ConfigurationRecorder")
	_pf_cfglib_all_supported(name)
	types := _pf_cfglib_group_resource_types(name)
	count(types) > 0
}
