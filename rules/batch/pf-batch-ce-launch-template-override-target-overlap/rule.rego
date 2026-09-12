package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-launch-template-override-target-overlap", "ERROR", name,
	"Properties.ComputeResources.LaunchTemplate.Overrides",
	sprintf("launch template overrides %v and %v both target %v (\"LaunchTemplate.overrides have duplicate targetInstanceTypes\")", [a.index, b.index, t]),
	"Give each override its own instance types",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_LaunchTemplateSpecificationOverride.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	some a in _pf_batch_lt_overrides(name)
	some b in _pf_batch_lt_overrides(name)
	a.index < b.index
	some t in _pf_batch_targets(a.value)
	t in _pf_batch_targets(b.value)
}
