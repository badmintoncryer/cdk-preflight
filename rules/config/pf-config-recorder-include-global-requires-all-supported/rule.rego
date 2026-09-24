package cdk_preflight

import rego.v1

_pf_cfgigr_err := "the recorder create fails: the flag is only read when every supported type is recorded"

violation contains make_diag_full("pf-config-recorder-include-global-requires-all-supported", "ERROR", name,
	"Properties.RecordingGroup.IncludeGlobalResourceTypes",
	sprintf("IncludeGlobalResourceTypes is true while AllSupported is not; %s", [_pf_cfgigr_err]),
	"Set AllSupported to true, or drop IncludeGlobalResourceTypes and name the global types in ResourceTypes",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-config-configurationrecorder-recordinggroup.html") if {
	some name in resources_of_type("AWS::Config::ConfigurationRecorder")
	object.get(_pf_cfglib_group(name), "IncludeGlobalResourceTypes", false) == true
	not _pf_cfglib_all_supported(name)
}
