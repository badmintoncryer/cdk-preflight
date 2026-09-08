package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-fargate-docker-volume", "ERROR", name,
	sprintf("Properties.Volumes.%d.DockerVolumeConfiguration", [v.index]),
	"A FARGATE task definition declares a Docker volume; RegisterTaskDefinition fails with \"Fargate compatible task definitions do not support dockerVolumeConfiguration\"",
	"Drop DockerVolumeConfiguration, or run the task on EC2",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecs_fargate(name)
	some v in flatten_list(name, "Properties.Volumes")
	_pf_ecs_ohas(v.value, "DockerVolumeConfiguration")
}
