package cdk_preflight

import rego.v1

_pf_ecsmemreq_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecs-taskdefinition-containerdefinition.html"

# When the task definition has no task-level Memory, every container must set
# Memory or MemoryReservation. Proving true absence needs the preprocessed
# document (input.resources): resolve() is undefined for a missing key and for
# an unresolvable value alike, so it cannot tell "absent" from "Ref to a
# parameter". The is_object guard fails closed if that internal shape changes.
_pf_ecsmemreq_task_memory_absent(name) if {
	props := input.resources[name].properties
	is_object(props)
	object.get(props, "Memory", "__pf_absent") == "__pf_absent"
}

violation contains make_diag_full("pf-ecs-container-memory-required", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d", [c.index]),
	sprintf("Container '%s' sets neither Memory nor MemoryReservation and the task has no task-level Memory; RegisterTaskDefinition fails with \"At least one of 'memory' or 'memoryReservation' must be specified\"", [cname]),
	"Set task-level Memory, or give the container Memory or MemoryReservation",
	_pf_ecsmemreq_url) if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	_pf_ecsmemreq_task_memory_absent(name)
	some c in flatten_list(name, "Properties.ContainerDefinitions")
	is_object(c.value)
	object.get(c.value, "Memory", null) == null
	object.get(c.value, "MemoryReservation", null) == null
	cname := object.get(c.value, "Name", "<unnamed>")
}
