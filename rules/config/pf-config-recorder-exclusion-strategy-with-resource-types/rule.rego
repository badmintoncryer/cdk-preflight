package cdk_preflight

import rego.v1

_pf_cfgesr_err := "the recorder create fails: an exclusion strategy reads ExclusionByResourceTypes, not ResourceTypes"

violation contains make_diag_full("pf-config-recorder-exclusion-strategy-with-resource-types", "ERROR", name,
	"Properties.RecordingGroup.ResourceTypes",
	sprintf("RecordingStrategy.UseOnly is EXCLUSION_BY_RESOURCE_TYPES but ResourceTypes lists %d type(s); %s", [count(types), _pf_cfgesr_err]),
	"Keep the types to skip in ExclusionByResourceTypes and drop RecordingGroup.ResourceTypes",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-config-configurationrecorder-recordingstrategy.html") if {
	some name in resources_of_type("AWS::Config::ConfigurationRecorder")
	_pf_cfglib_uses_only(name, "EXCLUSION_BY_RESOURCE_TYPES")
	types := _pf_cfglib_group_resource_types(name)
	count(types) > 0
}
