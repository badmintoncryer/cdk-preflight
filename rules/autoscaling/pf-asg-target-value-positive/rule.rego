package cdk_preflight

import rego.v1

# The service floor is effectively "positive" (8.5e-12); zero and
# negatives are rejected.
violation contains make_diag_full("pf-asg-target-value-positive", "ERROR", name,
	"Properties.TargetTrackingConfiguration.TargetValue",
	sprintf("TargetValue %v is not positive; the policy create fails with \"Target value must be between 8.51592E-12 and 1.174271E17\"", [v]),
	"Use a positive target value",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-autoscaling-scalingpolicy.html") if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	v := to_number(resolve(name, "Properties.TargetTrackingConfiguration.TargetValue"))
	v <= 0
}
