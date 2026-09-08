package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-awsvpc-hostname", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.Hostname", [c.index]),
	sprintf("Container '%s' sets Hostname while the task definition uses NetworkMode awsvpc; RegisterTaskDefinition fails with \"hostname is not supported on container when networkMode=awsvpc\"", [_pf_ecs_cname(c)]),
	"Drop Hostname, or use the bridge network mode",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	resolve(name, "Properties.NetworkMode") == "awsvpc"
	some c in _pf_ecs_containers(name)
	_pf_ecs_chas(c, "Hostname")
}
