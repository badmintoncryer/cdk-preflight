package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-dependson-container-missing", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.DependsOn", [c.index]),
	sprintf("Container '%s' depends on '%s', which is not declared in this task definition; RegisterTaskDefinition fails with \"Cannot depend on container %s because it does not exist\"", [_pf_ecs_cname(c), t, t]),
	"Point DependsOn at a container declared in the same task definition",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in _pf_ecs_containers(name)
	dep := _pf_ecs_cget(c, "DependsOn")
	is_array(dep)
	some d in dep
	t := object.get(d, "ContainerName", null)
	_pf_ecs_lit(t)
	not t in _pf_ecs_names(name)
}
