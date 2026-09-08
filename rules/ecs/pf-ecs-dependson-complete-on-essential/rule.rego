package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-dependson-complete-on-essential", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.DependsOn", [c.index]),
	sprintf("Container '%s' waits for the essential container '%s' to reach %s; RegisterTaskDefinition fails with \"A dependency container with SUCCESS or COMPLETE condition cannot be an essential container\"", [_pf_ecs_cname(c), t, cond]),
	"Set Essential to false on the depended-on container, or use the START / HEALTHY condition",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in _pf_ecs_containers(name)
	dep := _pf_ecs_cget(c, "DependsOn")
	is_array(dep)
	some d in dep
	cond := object.get(d, "Condition", null)
	cond in {"COMPLETE", "SUCCESS"}
	t := object.get(d, "ContainerName", null)
	_pf_ecs_lit(t)
	some tc in _pf_ecs_containers(name)
	object.get(tc.value, "Name", null) == t
	object.get(tc.value, "Essential", true) == true
}
