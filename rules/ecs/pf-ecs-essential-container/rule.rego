package cdk_preflight

import rego.v1

# Essential defaults to true, so the rule fires only when every container says
# Essential: false explicitly. A container whose Essential is unresolvable (or
# a non-boolean) breaks the `every`, and the rule skips — absence of an
# essential container cannot be proven then.
violation contains make_diag_full("pf-ecs-essential-container", "ERROR", name,
	"Properties.ContainerDefinitions",
	"Every container sets Essential: false; RegisterTaskDefinition fails with \"Task definition doesn't have any essential container\"",
	"Mark at least one container Essential: true, or omit Essential (it defaults to true)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-ecs-taskdefinition-containerdefinition.html") if {
	some name in resources_of_type("AWS::ECS::TaskDefinition")
	items := [c | some c in flatten_list(name, "Properties.ContainerDefinitions")]
	count(items) > 0
	every c in items {
		object.get(c.value, "Essential", null) == false
	}
}
