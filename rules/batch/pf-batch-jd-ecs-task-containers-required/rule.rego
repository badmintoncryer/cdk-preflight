package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-ecs-task-containers-required", "ERROR", name,
	"Properties.EcsProperties.TaskProperties",
	"a task element declares no containers (\"Number of containers must be between 1 and 10\")",
	"Add a container to the task element",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EcsTaskProperties.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some t in _pf_batch_ecs_tasks(name)
	count(object.get(t.value, "Containers", [])) == 0
}
