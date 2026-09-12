package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-launch-template-override-targets", "ERROR", name,
	"Properties.ComputeResources.LaunchTemplate.Overrides",
	sprintf("launch template override %v has no TargetInstanceTypes (\"LaunchTemplate.overrides.targetInstanceTypes[] is required\")", [o.index]),
	"Name the instance types the override applies to",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_LaunchTemplateSpecificationOverride.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	some o in _pf_batch_lt_overrides(name)
	count(object.get(o.value, "TargetInstanceTypes", [])) == 0
}
