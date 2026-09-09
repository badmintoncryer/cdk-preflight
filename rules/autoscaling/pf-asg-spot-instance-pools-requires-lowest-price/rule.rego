package cdk_preflight

import rego.v1

_pf_asgsip_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-spot-instance-pools-requires-lowest-price", "ERROR", name,
	"Properties.MixedInstancesPolicy.InstancesDistribution.SpotInstancePools",
	sprintf("SpotInstancePools is set while SpotAllocationStrategy is %s; the pool count only means something when Auto Scaling spreads across the cheapest pools, and the group create fails with \"SpotInstancePools option is only available with the lowest-price allocation strategy\"", [s]),
	"Drop SpotInstancePools, or set SpotAllocationStrategy to lowest-price", _pf_asgsip_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	not _pf_aslib_absent_at(name, ["MixedInstancesPolicy", "InstancesDistribution", "SpotInstancePools"])
	s := resolve(name, "Properties.MixedInstancesPolicy.InstancesDistribution.SpotAllocationStrategy")
	_pf_aslib_lit(s)
	s != "lowest-price"
}
