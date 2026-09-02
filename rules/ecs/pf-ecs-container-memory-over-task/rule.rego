package cdk_preflight

import rego.v1

# A single container's hard Memory limit cannot exceed the task-level Memory.
# Task Memory arrives as a string ("512"); to_number covers both spellings and
# makes the rule skip when either side is unresolvable or GB-suffixed.
violation contains make_diag_full("pf-ecs-container-memory-over-task", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.Memory", [c.index]),
	sprintf("Container '%s' sets Memory %v above the task-level Memory %v; RegisterTaskDefinition fails with \"The 'memory' setting for container '%s' is greater than for the task\"", [cname, cm, tm, cname]),
	"Lower the container Memory to at most the task-level Memory, or raise the task-level Memory",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ecs-taskdefinition.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	tm := to_number(resolve(name, "Properties.Memory"))
	some c in flatten_list(name, "Properties.ContainerDefinitions")
	is_object(c.value)
	cm := to_number(object.get(c.value, "Memory", null))
	cm > tm
	cname := object.get(c.value, "Name", "<unnamed>")
}
