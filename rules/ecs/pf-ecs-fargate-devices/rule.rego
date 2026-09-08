package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-fargate-devices", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.LinuxParameters.Devices", [c.index]),
	sprintf("Container '%s' sets LinuxParameters.Devices on a FARGATE task definition; RegisterTaskDefinition fails with \"Fargate compatible task definitions do not support devices\"", [_pf_ecs_cname(c)]),
	"Drop LinuxParameters.Devices, or run the task on EC2",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecs_fargate(name)
	some c in _pf_ecs_containers(name)
	lp := _pf_ecs_cget(c, "LinuxParameters")
	_pf_ecs_ohas(lp, "Devices")
}
