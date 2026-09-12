package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-launch-template-version", "ERROR", name,
	"Properties.ComputeResources.LaunchTemplate.Version",
	sprintf("launch template Version %v (\"LaunchTemplateVersion must be either empty or a number or $Default or $Latest\")", [v]),
	"Use the version number, $Default or $Latest",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_LaunchTemplateSpecification.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	v := _pf_batch_oget(_pf_batch_lt(name), "Version")
	_pf_batch_lit(v)
	not regex.match(`^([0-9]+|\$Default|\$Latest)$`, v)
}
