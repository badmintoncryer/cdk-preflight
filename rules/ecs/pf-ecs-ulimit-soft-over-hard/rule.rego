package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-ulimit-soft-over-hard", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.Ulimits", [c.index]),
	sprintf("Container '%s' sets the ulimit '%s' with SoftLimit %v above HardLimit %v; RegisterTaskDefinition fails with \"Soft limit exceeds hard limit for ulimit %s\"", [_pf_ecs_cname(c), un, s, h, un]),
	"Lower SoftLimit to at most HardLimit",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in _pf_ecs_containers(name)
	uls := _pf_ecs_cget(c, "Ulimits")
	is_array(uls)
	some u in uls
	s := to_number(object.get(u, "SoftLimit", null))
	h := to_number(object.get(u, "HardLimit", null))
	s > h
	un := object.get(u, "Name", "<unnamed>")
}
