package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-mi-requires-ecs-properties", "ERROR", name,
	"Properties.ContainerProperties",
	"a MANAGED_INSTANCES job definition uses ContainerProperties (\"Cannot use ECS containerProperties for MANAGED_INSTANCES\")",
	"Move the container into EcsProperties.TaskProperties",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_RegisterJobDefinition.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	_pf_batch_mi(name)
	_pf_batch_cp(name)
}
