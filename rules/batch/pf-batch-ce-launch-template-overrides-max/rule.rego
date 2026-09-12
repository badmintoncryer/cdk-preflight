package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-launch-template-overrides-max", "ERROR", name,
	"Properties.ComputeResources.LaunchTemplate.Overrides",
	sprintf("the launch template specification carries %v overrides (\"LaunchTemplate.overrides size cannot be greater than 10\")", [n]),
	"Keep the overrides list at 10 entries or fewer",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_LaunchTemplateSpecification.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	n := count(_pf_batch_lt_overrides(name))
	n > 10
}
