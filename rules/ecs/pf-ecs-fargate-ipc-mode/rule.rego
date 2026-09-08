package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-fargate-ipc-mode", "ERROR", name,
	"Properties.IpcMode",
	sprintf("IpcMode '%s' is set on a FARGATE task definition; RegisterTaskDefinition fails with \"Fargate compatible task definitions do not support ipcMode\"", [m]),
	"Drop IpcMode, or run the task on EC2",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecs_fargate(name)
	m := resolve(name, "Properties.IpcMode")
	is_string(m)
}
