package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-ecs-container-name-unique", "ERROR", name,
	"Properties.EcsProperties.TaskProperties",
	sprintf("container name %v is used %v times in one task element (\"Container names must be unique\")", [cn, n]),
	"Give every container in the task its own name",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_TaskContainerProperties.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some t in _pf_batch_ecs_tasks(name)
	cs := object.get(t.value, "Containers", [])
	some c in cs
	cn := object.get(c, "Name", null)
	_pf_batch_lit(cn)
	n := count([1 | some x in cs; object.get(x, "Name", null) == cn])
	n > 1
}
