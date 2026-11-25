package cdk_preflight

import rego.v1

# MemoryReservation is a soft floor and Memory a hard ceiling; the service
# rejects a floor above the ceiling. Indexing (not object.get(..., null), since
# to_number(null) is 0) keeps an omitted Memory undefined, so the rule skips
# when either value is absent or unresolvable (issue #392).
violation contains make_diag_full("pf-ecs-container-memory-reservation", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.MemoryReservation", [c.index]),
	sprintf("Container '%s' sets MemoryReservation %v above Memory %v; RegisterTaskDefinition fails with \"'memory' must be greater than or equal to 'memoryReservation'\"", [cname, mr, m]),
	"Lower MemoryReservation to at most Memory, or raise Memory",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecs-taskdefinition-containerdefinition.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some c in flatten_list(name, "Properties.ContainerDefinitions")
	is_object(c.value)
	m := _pf_tonum(c.value["Memory"])
	mr := _pf_tonum(c.value["MemoryReservation"])
	mr > m
	cname := object.get(c.value, "Name", "<unnamed>")
}
