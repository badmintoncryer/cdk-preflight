package cdk_preflight

import rego.v1

_pf_cfgrmd_continuous_only := {"AWS::Config::ResourceCompliance", "AWS::Config::ConformancePackCompliance", "AWS::Config::ConfigurationRecorder"}
_pf_cfgrmd_err := "the recorder create fails: those three types are always recorded continuously"

violation contains make_diag_full("pf-config-recorder-recording-mode-daily-resource-types", "ERROR", name,
	"Properties.RecordingMode.RecordingModeOverrides",
	sprintf("RecordingModeOverrides sets DAILY for %v; %s", [t, _pf_cfgrmd_err]),
	"Leave those types on the CONTINUOUS recording frequency",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-config-configurationrecorder-recordingmode.html") if {
	some name in resources_of_type("AWS::Config::ConfigurationRecorder")
	some o in flatten_list(name, "Properties.RecordingMode.RecordingModeOverrides")
	object.get(o.value, "RecordingFrequency", null) == "DAILY"
	some t in _pf_cfglib_list(o.value, "ResourceTypes")
	t in _pf_cfgrmd_continuous_only
}
