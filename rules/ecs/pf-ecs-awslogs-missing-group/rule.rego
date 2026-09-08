package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-awslogs-missing-group", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.LogConfiguration.Options", [c.index]),
	sprintf("Container '%s' uses the awslogs driver without the awslogs-group option; RegisterTaskDefinition fails with \"Log driver awslogs requires options: awslogs-group\"", [_pf_ecs_cname(c)]),
	"Add awslogs-group (and awslogs-region) to LogConfiguration.Options",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in _pf_ecs_containers(name)
	lc := _pf_ecs_cget(c, "LogConfiguration")
	_pf_ecs_oget(lc, "LogDriver") == "awslogs"
	not _pf_ecs_ohas(object.get(lc, "Options", {}), "awslogs-group")
}
