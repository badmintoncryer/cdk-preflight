package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-ce-name", "ERROR", name,
	"Properties.ComputeEnvironmentName",
	sprintf("ComputeEnvironmentName '%s' is rejected by the service: letters, numbers, hyphen and underscore, at most 128 characters", [v]),
	"Rename it to satisfy letters, numbers, hyphen and underscore, at most 128 characters",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_CreateComputeEnvironment.html") if {
	some name in resources_of_type("AWS::Batch::ComputeEnvironment")
	v := resolve(name, "Properties.ComputeEnvironmentName")
	is_string(v)
	not regex.match(`^[a-zA-Z0-9_-]{1,128}$`, v)
}
