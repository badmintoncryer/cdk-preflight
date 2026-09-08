package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-fargate-host-source-path", "ERROR", name,
	sprintf("Properties.Volumes.%d.Host.SourcePath", [v.index]),
	"A FARGATE task definition binds a host path through Volumes[].Host.SourcePath; RegisterTaskDefinition fails with \"Fargate compatible task definitions do not support sourcePath\"",
	"Drop Host.SourcePath (bind mounts need EC2), or use an EFS volume",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecs_fargate(name)
	some v in flatten_list(name, "Properties.Volumes")
	h := _pf_ecs_oget(v.value, "Host")
	_pf_ecs_ohas(h, "SourcePath")
}
