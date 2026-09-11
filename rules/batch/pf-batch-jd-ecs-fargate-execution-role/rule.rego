package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-ecs-fargate-execution-role", "ERROR", name,
	"Properties.EcsProperties.TaskProperties",
	"a Fargate task element has no ExecutionRoleArn (\"executionRoleArn is required for Fargate jobs.\")",
	"Set EcsProperties.TaskProperties[].ExecutionRoleArn",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EcsTaskProperties.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_fargate(name)
	some t in _pf_batch_ecs_tasks(name)
	not _pf_batch_ohas(t.value, "ExecutionRoleArn")
}
