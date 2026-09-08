package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-dependson-healthy-without-healthcheck", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.DependsOn", [c.index]),
	sprintf("Container '%s' waits for '%s' to become HEALTHY but that container defines no HealthCheck; RegisterTaskDefinition fails with \"A dependency container with HEALTHY condition must have health check configured\"", [_pf_ecs_cname(c), t]),
	"Add a HealthCheck to the depended-on container, or use the START condition",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in _pf_ecs_containers(name)
	dep := _pf_ecs_cget(c, "DependsOn")
	is_array(dep)
	some d in dep
	object.get(d, "Condition", null) == "HEALTHY"
	t := object.get(d, "ContainerName", null)
	_pf_ecs_lit(t)
	some tc in _pf_ecs_containers(name)
	object.get(tc.value, "Name", null) == t
	not _pf_ecs_chas(tc, "HealthCheck")
}
