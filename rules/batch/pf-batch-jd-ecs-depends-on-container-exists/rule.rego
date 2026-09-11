package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-batch-jd-ecs-depends-on-container-exists", "ERROR", name,
	"Properties.EcsProperties.TaskProperties",
	sprintf("a container depends on %v, which is not declared in the task element (\"containerName %v must reference a defined container.\")", [dep, dep]),
	"Point DependsOn at a container of the same task",
	"https://docs.aws.amazon.com/batch/latest/APIReference/API_TaskContainerDependency.html") if {
	some name in resources_of_type("AWS::Batch::JobDefinition")
	some t in _pf_batch_ecs_tasks(name)
	some c in object.get(t.value, "Containers", [])
	some d in object.get(c, "DependsOn", [])
	dep := object.get(d, "ContainerName", null)
	_pf_batch_lit(dep)
	not dep in _pf_batch_ecs_names(t)
}
