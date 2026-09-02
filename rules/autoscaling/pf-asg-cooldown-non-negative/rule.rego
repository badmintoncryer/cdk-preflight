package cdk_preflight

import rego.v1

# Cooldown is a string in the schema; only the service knows it is a
# non-negative integer.
violation contains make_diag_full("pf-asg-cooldown-non-negative", "ERROR", name,
	"Properties.Cooldown",
	sprintf("Cooldown %v is negative; the group create fails with \"Member must have value greater than or equal to 0\"", [c]),
	"Use zero or a positive number of seconds",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-autoscaling-autoscalinggroup.html") if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	c := to_number(resolve(name, "Properties.Cooldown"))
	c < 0
}
