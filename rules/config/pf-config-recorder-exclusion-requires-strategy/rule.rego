package cdk_preflight

import rego.v1

_pf_cfgers_err := "the recorder create fails: the exclusion list is only read under that strategy"

violation contains make_diag_full("pf-config-recorder-exclusion-requires-strategy", "ERROR", name,
	"Properties.RecordingGroup.ExclusionByResourceTypes",
	sprintf("ExclusionByResourceTypes is set without RecordingStrategy.UseOnly EXCLUSION_BY_RESOURCE_TYPES; %s", [_pf_cfgers_err]),
	"Add RecordingGroup.RecordingStrategy.UseOnly: EXCLUSION_BY_RESOURCE_TYPES",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-config-configurationrecorder-exclusionbyresourcetypes.html") if {
	some name in resources_of_type("AWS::Config::ConfigurationRecorder")
	_pf_cfglib_obj(_pf_cfglib_group(name), "ExclusionByResourceTypes")
	not _pf_cfglib_uses_only(name, "EXCLUSION_BY_RESOURCE_TYPES")
}
