package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-fargate-container-cpu-over-task", "ERROR", name,
	"Properties.ContainerDefinitions",
	sprintf("The containers reserve %v CPU units in total but the task definition allocates %v; RegisterTaskDefinition fails with \"The sum of all container 'cpu' values cannot be greater than the task-level 'cpu' value\"", [total, tc]),
	"Lower the container Cpu values, or raise the task-level Cpu",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	tc := to_number(resolve(name, "Properties.Cpu"))
	total := sum([n | some c in _pf_ecs_containers(name); n := to_number(object.get(c.value, "Cpu", 0))])
	total > tc
}
