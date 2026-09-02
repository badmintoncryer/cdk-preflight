package cdk_preflight

import rego.v1

# The schema types it as a bare integer with no floor; zero is the
# service default, so only negatives are claimed.
violation contains make_diag_full("pf-asg-health-check-grace-period", "ERROR", name,
	"Properties.HealthCheckGracePeriod",
	sprintf("HealthCheckGracePeriod %v is negative; the group create fails with \"Grace period must be a positive integer.\"", [g]),
	"Use zero or a positive number of seconds",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-autoscaling-autoscalinggroup.html") if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	g := to_number(resolve(name, "Properties.HealthCheckGracePeriod"))
	g < 0
}
