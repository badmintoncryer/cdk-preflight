package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ecs-fargate-inference-accelerator", "ERROR", name,
	"Properties.InferenceAccelerators",
	"The task definition declares InferenceAccelerators, but Amazon Elastic Inference is retired; RegisterTaskDefinition fails with \"Unsupported field 'inferenceAccelerators'\"",
	"Drop InferenceAccelerators; Amazon Elastic Inference is no longer available",
	"https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	ia := _pf_ecs_get(name, "InferenceAccelerators")
	count(ia) > 0
}
