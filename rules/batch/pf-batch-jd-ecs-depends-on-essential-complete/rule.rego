package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-ecs-depends-on-essential-complete", "ERROR", name,
	"Properties.EcsProperties.TaskProperties",
	sprintf("a container waits for essential container %v with condition %v (\"The container target of a dependency can not have condition %v if the target is essential\")", [dep, cond, cond]),
	"Depend on a non-essential container, or use condition START",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_TaskContainerDependency.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some t in _pf_batch_ecs_tasks(name)
	some c in object.get(t.value, "Containers", [])
	some d in object.get(c, "DependsOn", [])
	cond := object.get(d, "Condition", null)
	cond in {"COMPLETE", "SUCCESS"}
	dep := object.get(d, "ContainerName", null)
	_pf_batch_lit(dep)
	some target in object.get(t.value, "Containers", [])
	object.get(target, "Name", null) == dep
	object.get(target, "Essential", true) == true
}
