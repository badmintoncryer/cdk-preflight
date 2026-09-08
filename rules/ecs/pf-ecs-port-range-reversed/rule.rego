package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-port-range-reversed", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.PortMappings", [c.index]),
	sprintf("Container '%s' declares the port range '%s' where the first port is not below the last; RegisterTaskDefinition fails with \"Invalid 'containerPortRange' setting\"", [_pf_ecs_cname(c), r]),
	"Write ContainerPortRange as \"<low>-<high>\"",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in _pf_ecs_containers(name)
	pms := _pf_ecs_cget(c, "PortMappings")
	is_array(pms)
	some pm in pms
	r := object.get(pm, "ContainerPortRange", null)
	_pf_ecs_lit(r)
	parts := split(r, "-")
	count(parts) == 2
	to_number(parts[0]) >= to_number(parts[1])
}
