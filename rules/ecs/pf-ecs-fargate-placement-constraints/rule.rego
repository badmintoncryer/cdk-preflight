package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-fargate-placement-constraints", "ERROR", name,
	"Properties.PlacementConstraints",
	"A FARGATE task definition declares PlacementConstraints; RegisterTaskDefinition fails with \"Fargate compatible task definitions do not support constraints\"",
	"Drop PlacementConstraints, or run the task on EC2",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecs_fargate(name)
	pc := _pf_ecs_get(name, "PlacementConstraints")
	count(pc) > 0
}
