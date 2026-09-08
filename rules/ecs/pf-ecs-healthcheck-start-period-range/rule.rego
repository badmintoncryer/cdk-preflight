package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-healthcheck-start-period-range", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.HealthCheck.StartPeriod", [c.index]),
	sprintf("Container '%s' sets HealthCheck.StartPeriod to %v; RegisterTaskDefinition accepts only 0-300", [_pf_ecs_cname(c), v]),
	"Set HealthCheck.StartPeriod to a value between 0 and 300",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in _pf_ecs_containers(name)
	hc := _pf_ecs_cget(c, "HealthCheck")
	v := to_number(_pf_ecs_oget(hc, "StartPeriod"))
	_pf_ecs_outside(v, 0, 300)
}
