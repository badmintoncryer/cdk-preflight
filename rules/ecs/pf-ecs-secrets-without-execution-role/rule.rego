package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-secrets-without-execution-role", "ERROR", name,
	"Properties.ExecutionRoleArn",
	sprintf("Container '%s' injects Secrets but the task definition sets no ExecutionRoleArn; RegisterTaskDefinition fails with \"When you are specifying container secrets, you must also specify a value for 'executionRoleArn'\"", [_pf_ecs_cname(c)]),
	"Set ExecutionRoleArn to a task execution role that can read the secret",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	not _pf_ecs_has(name, "ExecutionRoleArn")
	some c in _pf_ecs_containers(name)
	s := _pf_ecs_cget(c, "Secrets")
	count(s) > 0
}
