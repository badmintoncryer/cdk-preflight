package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-ecs-depends-on-single-container", "ERROR", name,
	"Properties.EcsProperties.TaskProperties",
	"a task element with a single container uses DependsOn (\"Container dependency can not be used in a single-container job.\")",
	"Remove DependsOn, or add the container it waits for",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_TaskContainerDependency.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some t in _pf_batch_ecs_tasks(name)
	cs := object.get(t.value, "Containers", [])
	count(cs) == 1
	some c in cs
	_pf_batch_ohas(c, "DependsOn")
}
