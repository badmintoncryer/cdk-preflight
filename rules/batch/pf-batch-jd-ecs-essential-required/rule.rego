package cdk_preflight

import rego.v1

# Only explicit false counts: the API treats a missing Essential as true.
violation contains make_diag_full("pf-batch-jd-ecs-essential-required", "ERROR", name,
	"Properties.EcsProperties.TaskProperties",
	"every container in the task element is marked Essential: false (\"At least one container must be set as essential\")",
	"Mark one container Essential: true",
	"https://docs.aws.amazon.com/batch/latest/userguide/multi-container-jobs.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some t in _pf_batch_ecs_tasks(name)
	cs := object.get(t.value, "Containers", [])
	count(cs) > 0
	count([1 | some c in cs; object.get(c, "Essential", true) == false]) == count(cs)
}
