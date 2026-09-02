package cdk_preflight

import rego.v1

# One diagnostic per duplicated later occurrence; only literal string names
# can be compared, so a Ref-valued Name skips its pairs.
violation contains make_diag_full("pf-ecs-duplicate-container-names", "ERROR", name,
	sprintf("Properties.ContainerDefinitions.%d.Name", [b.index]),
	sprintf("Container name '%s' appears more than once; RegisterTaskDefinition fails with \"Container names must be unique within a task definition\"", [na]),
	"Give every container in the task definition a distinct Name",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecs-taskdefinition-containerdefinition.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	some a in flatten_list(name, "Properties.ContainerDefinitions")
	some b in flatten_list(name, "Properties.ContainerDefinitions")
	a.index < b.index
	na := object.get(a.value, "Name", null)
	is_string(na)
	na == object.get(b.value, "Name", null)
}
