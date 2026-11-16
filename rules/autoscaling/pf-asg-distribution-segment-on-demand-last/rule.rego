package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-asg-distribution-segment-on-demand-last", "ERROR", name,
	sprintf("Properties.MixedInstancesPolicy.InstancesDistribution.DistributionSegments.%d.TargetCapacityTypes", [s.index]),
	"on-demand is not the last entry of TargetCapacityTypes; CreateAutoScalingGroup fails with \"If 'on-demand' is specified in TargetCapacityTypes, it must be the last element.\"",
	"Move on-demand to the end of the list (it is the fallback after the reserved capacity types)",
	"https://docs.aws.amazon.com/autoscaling/ec2/userguide/distribution-segments.html") if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	some s in flatten_list(name, "Properties.MixedInstancesPolicy.InstancesDistribution.DistributionSegments")
	types := object.get(s.value, "TargetCapacityTypes", null)
	is_array(types)
	# only a list written entirely as literals, so positions are the deployed positions
	every t in types { is_string(t) }
	some i, t in types
	t == "on-demand"
	i < count(types) - 1
}
