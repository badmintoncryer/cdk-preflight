package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-launch-template-override-target-subset", "ERROR", name,
	"Properties.ComputeResources.LaunchTemplate.Overrides",
	sprintf("launch template override %v targets %v, which the compute environment does not run (\"LaunchTemplate.overrides have targetInstanceTypes that do not match\")", [o.index, t]),
	"Target only instance types the compute environment lists",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_LaunchTemplateSpecificationOverride.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	its := {v | some v in _pf_batch_ce_itypes(name)}
	count(its) > 0
	some o in _pf_batch_lt_overrides(name)
	some t in _pf_batch_targets(o.value)
	not t in its
}
