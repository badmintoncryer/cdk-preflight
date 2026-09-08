package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-port-mapping-duplicate-name", "ERROR", name,
	"Properties.ContainerDefinitions",
	sprintf("The port mapping name '%s' is used more than once in the task definition; RegisterTaskDefinition fails with \"port mapping name is already used\"", [n]),
	"Give every port mapping in the task definition a distinct Name",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	pms := _pf_ecs_portmappings(name)
	some i, j
	i < j
	n := object.get(pms[i], "Name", null)
	_pf_ecs_lit(n)
	n == object.get(pms[j], "Name", null)
}
