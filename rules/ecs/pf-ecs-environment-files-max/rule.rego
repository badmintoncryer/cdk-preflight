package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-environment-files-max", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.EnvironmentFiles", [c.index]),
	sprintf("Container '%s' loads %d environment files; RegisterTaskDefinition fails with \"The maximum number of environment files was exceeded. Specify ten or less and try again\"", [_pf_ecs_cname(c), count(efs)]),
	"Reduce EnvironmentFiles to 10 entries",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in _pf_ecs_containers(name)
	efs := _pf_ecs_cget(c, "EnvironmentFiles")
	count(efs) > 10
}
