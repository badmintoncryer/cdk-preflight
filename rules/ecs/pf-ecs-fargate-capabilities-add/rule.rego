package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-fargate-capabilities-add", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.LinuxParameters.Capabilities.Add", [c.index]),
	sprintf("Container '%s' adds the Linux capability '%s'; on Fargate only SYS_PTRACE can be added and RegisterTaskDefinition fails with \"%s is not allowed on Fargate.\"", [_pf_ecs_cname(c), cap, cap]),
	"Remove every capability other than SYS_PTRACE, or run the task on EC2",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecs_fargate(name)
	some c in _pf_ecs_containers(name)
	lp := _pf_ecs_cget(c, "LinuxParameters")
	caps := _pf_ecs_oget(lp, "Capabilities")
	add := _pf_ecs_oget(caps, "Add")
	is_array(add)
	some cap in add
	_pf_ecs_lit(cap)
	cap != "SYS_PTRACE"
}
