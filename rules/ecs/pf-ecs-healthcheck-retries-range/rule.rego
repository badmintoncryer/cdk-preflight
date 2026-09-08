package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-healthcheck-retries-range", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.HealthCheck.Retries", [c.index]),
	sprintf("Container '%s' sets HealthCheck.Retries to %v; RegisterTaskDefinition accepts only 1-10", [_pf_ecs_cname(c), v]),
	"Set HealthCheck.Retries to a value between 1 and 10",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in _pf_ecs_containers(name)
	hc := _pf_ecs_cget(c, "HealthCheck")
	v := to_number(_pf_ecs_oget(hc, "Retries"))
	_pf_ecs_outside(v, 1, 10)
}
