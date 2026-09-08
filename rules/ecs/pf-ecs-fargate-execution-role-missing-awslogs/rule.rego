package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-fargate-execution-role-missing-awslogs", "ERROR", name,
	"Properties.ExecutionRoleArn",
	sprintf("Container '%s' logs through the awslogs driver on a FARGATE task definition that sets no ExecutionRoleArn; RegisterTaskDefinition fails with \"Fargate requires task definition to have execution role ARN to support log driver awslogs\"", [_pf_ecs_cname(c)]),
	"Set ExecutionRoleArn to a task execution role that can write to CloudWatch Logs",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecs_fargate(name)
	not _pf_ecs_has(name, "ExecutionRoleArn")
	some c in _pf_ecs_containers(name)
	lc := _pf_ecs_cget(c, "LogConfiguration")
	_pf_ecs_oget(lc, "LogDriver") == "awslogs"
}
