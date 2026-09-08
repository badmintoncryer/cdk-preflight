package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-restart-policy-attempt-period-range", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.RestartPolicy.RestartAttemptPeriod", [c.index]),
	sprintf("Container '%s' sets RestartAttemptPeriod to %v; RegisterTaskDefinition fails with \"the 'restartAttemptPeriod' setting for container '%s' must be between 60 and 1800\"", [_pf_ecs_cname(c), v, _pf_ecs_cname(c)]),
	"Set RestartAttemptPeriod to a value between 60 and 1800",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in _pf_ecs_containers(name)
	rp := _pf_ecs_cget(c, "RestartPolicy")
	v := to_number(_pf_ecs_oget(rp, "RestartAttemptPeriod"))
	_pf_ecs_outside(v, 60, 1800)
}
