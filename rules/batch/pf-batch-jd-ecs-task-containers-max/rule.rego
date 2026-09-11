package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-ecs-task-containers-max", "ERROR", name,
	"Properties.EcsProperties.TaskProperties",
	sprintf("a task element declares %v containers (\"Number of containers must be between 1 and 10\")", [n]),
	"Split the job, or keep at most 10 containers per task",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_EcsProperties.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some t in _pf_batch_ecs_tasks(name)
	n := count(object.get(t.value, "Containers", []))
	n > 10
}
