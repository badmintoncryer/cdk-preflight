package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-awslogs-fargate-missing-stream-prefix", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.LogConfiguration.Options", [c.index]),
	sprintf("Container '%s' logs through awslogs on a FARGATE task definition without awslogs-stream-prefix; RegisterTaskDefinition fails with \"Fargate requires log configuration options to include awslogs-stream-prefix\"", [_pf_ecs_cname(c)]),
	"Add awslogs-stream-prefix to LogConfiguration.Options",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecs_fargate(name)
	some c in _pf_ecs_containers(name)
	lc := _pf_ecs_cget(c, "LogConfiguration")
	_pf_ecs_oget(lc, "LogDriver") == "awslogs"
	not _pf_ecs_ohas(object.get(lc, "Options", {}), "awslogs-stream-prefix")
}
