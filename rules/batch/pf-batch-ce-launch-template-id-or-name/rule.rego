package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-launch-template-id-or-name", "ERROR", name,
	"Properties.ComputeResources.LaunchTemplate",
	sprintf("the launch template specification names %v of LaunchTemplateId / LaunchTemplateName (\"One of LaunchTemplateId and LaunchTemplateName or LaunchTemplate.overrides should be provided\")", [count(keys)]),
	"Identify the launch template by its id or by its name, not both and not neither",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_LaunchTemplateSpecification.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	lt := _pf_batch_lt(name)
	keys := [k | some k in ["LaunchTemplateId", "LaunchTemplateName"]; _pf_batch_ohas(lt, k)]
	count(keys) != 1
}
