package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-fargate-max-swap", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.LinuxParameters.MaxSwap", [c.index]),
	sprintf("Container '%s' sets LinuxParameters.MaxSwap on a FARGATE task definition; RegisterTaskDefinition fails with \"Fargate compatible task definitions do not support maxSwap\"", [_pf_ecs_cname(c)]),
	"Drop LinuxParameters.MaxSwap and Swappiness, or run the task on EC2",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecs_fargate(name)
	some c in _pf_ecs_containers(name)
	lp := _pf_ecs_cget(c, "LinuxParameters")
	_pf_ecs_ohas(lp, "MaxSwap")
}
