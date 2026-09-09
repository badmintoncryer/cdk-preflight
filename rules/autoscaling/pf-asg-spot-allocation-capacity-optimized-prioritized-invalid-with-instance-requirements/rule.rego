package cdk_preflight

import rego.v1

_pf_asgsap_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

_pf_asgsap_usesir(name) if {
	some o in _pf_aslib_overrides(name)
	is_object(o)
	is_object(object.get(o, "InstanceRequirements", null))
}

violation contains make_diag_full("pf-asg-spot-allocation-capacity-optimized-prioritized-invalid-with-instance-requirements", "ERROR", name,
	"Properties.MixedInstancesPolicy.InstancesDistribution.SpotAllocationStrategy",
	"SpotAllocationStrategy is capacity-optimized-prioritized while the overrides pick instances by requirements, so there is no priority order to follow; the group create fails with \"The capacity-optimized-prioritized allocation strategy is not compatible with instance requirements\"",
	"Use lowest-price, capacity-optimized or price-capacity-optimized", _pf_asgsap_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	resolve(name, "Properties.MixedInstancesPolicy.InstancesDistribution.SpotAllocationStrategy") == "capacity-optimized-prioritized"
	_pf_asgsap_usesir(name)
}
