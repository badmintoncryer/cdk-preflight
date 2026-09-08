package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-fargate-docker-security-options", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.DockerSecurityOptions", [c.index]),
	sprintf("Container '%s' sets DockerSecurityOptions on a FARGATE task definition; RegisterTaskDefinition fails with \"Fargate compatible task definitions do not support dockerSecurityOptions\"", [_pf_ecs_cname(c)]),
	"Drop DockerSecurityOptions, or run the task on EC2",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecs_fargate(name)
	some c in _pf_ecs_containers(name)
	_pf_ecs_chas(c, "DockerSecurityOptions")
}
