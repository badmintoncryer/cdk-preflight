package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-fargate-pid-mode-host", "ERROR", name,
	"Properties.PidMode",
	"PidMode is 'host' on a FARGATE task definition; only 'task' is supported and RegisterTaskDefinition fails with \"Tasks using the Fargate launch type do not support pidMode 'host'\"",
	"Use PidMode 'task', or run the task on EC2",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecs_fargate(name)
	resolve(name, "Properties.PidMode") == "host"
}
