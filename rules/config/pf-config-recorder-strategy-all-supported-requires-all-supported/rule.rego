package cdk_preflight

import rego.v1

_pf_cfgsas_err := "the recorder create fails: the strategy and the flag have to say the same thing"

violation contains make_diag_full("pf-config-recorder-strategy-all-supported-requires-all-supported", "ERROR", name,
	"Properties.RecordingGroup.RecordingStrategy.UseOnly",
	sprintf("RecordingStrategy.UseOnly is ALL_SUPPORTED_RESOURCE_TYPES while AllSupported is not true; %s", [_pf_cfgsas_err]),
	"Set RecordingGroup.AllSupported to true, or pick another RecordingStrategy",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-config-configurationrecorder-recordingstrategy.html") if {
	some name in resources_of_type("AWS::Config::ConfigurationRecorder")
	_pf_cfglib_uses_only(name, "ALL_SUPPORTED_RESOURCE_TYPES")
	not _pf_cfglib_all_supported(name)
}
