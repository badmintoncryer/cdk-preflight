package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-launch-template-override-id-or-name", "ERROR", name,
	"Properties.ComputeResources.LaunchTemplate.Overrides",
	sprintf("launch template override %v sets both LaunchTemplateId and LaunchTemplateName (\"LaunchTemplate.overrides should have either LaunchTemplateId or LaunchTemplateName\")", [o.index]),
	"Identify the override template by its id or by its name, not both",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_LaunchTemplateSpecificationOverride.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	some o in _pf_batch_lt_overrides(name)
	_pf_batch_ohas(o.value, "LaunchTemplateId")
	_pf_batch_ohas(o.value, "LaunchTemplateName")
}
