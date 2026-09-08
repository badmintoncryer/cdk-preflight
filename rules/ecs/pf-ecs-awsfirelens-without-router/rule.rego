package cdk_preflight

import rego.v1

# Does any container in the task definition act as the FireLens router?
_pf_ecs_firelens(name) if {
	some c in _pf_ecs_containers(name)
	_pf_ecs_chas(c, "FirelensConfiguration")
}

violation contains make_diag_full("pf-ecs-awsfirelens-without-router", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.LogConfiguration.LogDriver", [c.index]),
	sprintf("Container '%s' logs through awsfirelens but no container declares FirelensConfiguration; RegisterTaskDefinition fails with \"When awsfirelens log driver is specified in log configuration, a firelens configuration object must be specified\"", [_pf_ecs_cname(c)]),
	"Add a container with FirelensConfiguration to the task definition",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in _pf_ecs_containers(name)
	lc := _pf_ecs_cget(c, "LogConfiguration")
	_pf_ecs_oget(lc, "LogDriver") == "awsfirelens"
	not _pf_ecs_firelens(name)
}
