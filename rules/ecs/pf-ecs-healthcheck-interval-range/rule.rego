package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-healthcheck-interval-range", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.HealthCheck.Interval", [c.index]),
	sprintf("Container '%s' sets HealthCheck.Interval to %v; RegisterTaskDefinition accepts only 5-300", [_pf_ecs_cname(c), v]),
	"Set HealthCheck.Interval to a value between 5 and 300",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in _pf_ecs_containers(name)
	hc := _pf_ecs_cget(c, "HealthCheck")
	v := to_number(_pf_ecs_oget(hc, "Interval"))
	_pf_ecs_outside(v, 5, 300)
}
