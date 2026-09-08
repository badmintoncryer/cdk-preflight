package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-healthcheck-timeout-range", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.HealthCheck.Timeout", [c.index]),
	sprintf("Container '%s' sets HealthCheck.Timeout to %v; RegisterTaskDefinition accepts only 2-60", [_pf_ecs_cname(c), v]),
	"Set HealthCheck.Timeout to a value between 2 and 60",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in _pf_ecs_containers(name)
	hc := _pf_ecs_cget(c, "HealthCheck")
	v := to_number(_pf_ecs_oget(hc, "Timeout"))
	_pf_ecs_outside(v, 2, 60)
}
