package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-fargate-links", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.Links", [c.index]),
	sprintf("Container '%s' sets Links while the task definition uses NetworkMode awsvpc; RegisterTaskDefinition fails with \"Links are not supported when networkMode=awsvpc\"", [_pf_ecs_cname(c)]),
	"Drop Links; containers in an awsvpc task share a network namespace and reach each other on localhost",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	resolve(name, "Properties.NetworkMode") == "awsvpc"
	some c in _pf_ecs_containers(name)
	l := _pf_ecs_cget(c, "Links")
	count(l) > 0
}
