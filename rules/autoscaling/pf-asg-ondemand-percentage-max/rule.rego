package cdk_preflight

import rego.v1

# A percentage split cannot exceed 100; the schema has no maximum.
violation contains make_diag_full("pf-asg-ondemand-percentage-max", "ERROR", name,
	"Properties.MixedInstancesPolicy.InstancesDistribution.OnDemandPercentageAboveBaseCapacity",
	sprintf("OnDemandPercentageAboveBaseCapacity %v is over 100; the group create fails with \"Member must have value less than or equal to 100\"", [p]),
	"Use a percentage between 0 and 100",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-autoscaling-autoscalinggroup-instancesdistribution.html") if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	p := to_number(resolve(name, "Properties.MixedInstancesPolicy.InstancesDistribution.OnDemandPercentageAboveBaseCapacity"))
	p > 100
}
