package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-host-network-host-port-mismatch", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.PortMappings", [c.index]),
	sprintf("Container '%s' maps container port %v to host port %v while the task definition uses NetworkMode host; RegisterTaskDefinition fails with \"When networkMode=host, the host ports and container ports in port mappings must match\"", [_pf_ecs_cname(c), cp, hp]),
	"Drop HostPort, or set it to the same value as ContainerPort",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	resolve(name, "Properties.NetworkMode") == "host"
	some c in _pf_ecs_containers(name)
	pms := _pf_ecs_cget(c, "PortMappings")
	is_array(pms)
	some pm in pms
	cp := to_number(object.get(pm, "ContainerPort", null))
	hp := to_number(object.get(pm, "HostPort", null))
	cp != hp
}
