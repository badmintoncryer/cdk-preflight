package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-port-range-with-host-port", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.PortMappings", [c.index]),
	sprintf("Container '%s' declares both ContainerPortRange and a single port; RegisterTaskDefinition fails with \"cannot specify both single port and port range\"", [_pf_ecs_cname(c)]),
	"Use either ContainerPortRange or ContainerPort/HostPort, not both",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in _pf_ecs_containers(name)
	pms := _pf_ecs_cget(c, "PortMappings")
	is_array(pms)
	some pm in pms
	_pf_ecs_ohas(pm, "ContainerPortRange")
	some k in {"HostPort", "ContainerPort"}
	_pf_ecs_ohas(pm, k)
}
