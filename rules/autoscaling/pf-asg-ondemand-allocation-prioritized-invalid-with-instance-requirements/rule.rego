package cdk_preflight

import rego.v1

_pf_asgoap_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

_pf_asgoap_usesir(name) if {
	some o in _pf_aslib_overrides(name)
	is_object(o)
	is_object(object.get(o, "InstanceRequirements", null))
}

violation contains make_diag_full("pf-asg-ondemand-allocation-prioritized-invalid-with-instance-requirements", "ERROR", name,
	"Properties.MixedInstancesPolicy.InstancesDistribution.OnDemandAllocationStrategy",
	"OnDemandAllocationStrategy is prioritized while the overrides pick instances by requirements, so there is no priority order to follow; the group create fails with \"The prioritized allocation strategy is not compatible with instance requirements. Valid options are [lowest-price]\"",
	"Use lowest-price, or list instance types in priority order instead of requirements", _pf_asgoap_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	resolve(name, "Properties.MixedInstancesPolicy.InstancesDistribution.OnDemandAllocationStrategy") == "prioritized"
	_pf_asgoap_usesir(name)
}
