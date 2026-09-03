package cdk_preflight

import rego.v1

_pf_batchfer_fargate(name) if {
	some pc in flatten_list(name, "Properties.PlatformCapabilities")
	pc.value == "FARGATE"
}

violation contains make_diag_full("pf-batch-fargate-execution-role", "ERROR", name,
	"Properties.ContainerProperties.ExecutionRoleArn",
	"PlatformCapabilities includes FARGATE but ExecutionRoleArn is missing (\"executionRoleArn is required for Fargate jobs.\")",
	"Set ContainerProperties.ExecutionRoleArn",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RegisterJobDefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batchfer_fargate(name)
	cp := input.resources[name].properties.ContainerProperties
	is_object(cp)
	object.get(cp, "ExecutionRoleArn", "__pf_absent") == "__pf_absent"
}
