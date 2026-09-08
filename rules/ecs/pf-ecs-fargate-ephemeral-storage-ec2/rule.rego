package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-fargate-ephemeral-storage-ec2", "ERROR", name,
	"Properties.EphemeralStorage",
	"EphemeralStorage is set on a task definition that does not require FARGATE; RegisterTaskDefinition fails with \"Tasks using the EC2 launch type do not support EphemeralStorage\"",
	"Drop EphemeralStorage, or add FARGATE to RequiresCompatibilities",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecs_has(name, "EphemeralStorage")
	rc := resolve(name, "Properties.RequiresCompatibilities")
	is_array(rc)
	not "FARGATE" in rc
}
