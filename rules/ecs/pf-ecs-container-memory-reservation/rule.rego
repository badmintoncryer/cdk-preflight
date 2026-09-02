package cdk_preflight

import rego.v1

# MemoryReservation is a soft floor and Memory a hard ceiling; the service
# rejects a floor above the ceiling. to_number fails (and the rule skips) when
# either value is absent or unresolvable.
violation contains make_diag_full("pf-ecs-container-memory-reservation", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.MemoryReservation", [c.index]),
	sprintf("Container '%s' sets MemoryReservation %v above Memory %v; RegisterTaskDefinition fails with \"'memory' must be greater than or equal to 'memoryReservation'\"", [cname, mr, m]),
	"Lower MemoryReservation to at most Memory, or raise Memory",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecs-taskdefinition-containerdefinition.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in flatten_list(name, "Properties.ContainerDefinitions")
	is_object(c.value)
	m := to_number(object.get(c.value, "Memory", null))
	mr := to_number(object.get(c.value, "MemoryReservation", null))
	mr > m
	cname := object.get(c.value, "Name", "<unnamed>")
}
