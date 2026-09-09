package cdk_preflight

import rego.v1

_pf_asgowu_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

_pf_asgowu_weighted(name) := count([1 |
	some o in _pf_aslib_overrides(name)
	is_object(o)
	object.get(o, "WeightedCapacity", "__pf_absent") != "__pf_absent"
])

violation contains make_diag_full("pf-asg-overrides-weighted-capacity-uniform", "ERROR", name,
	"Properties.MixedInstancesPolicy.LaunchTemplate.Overrides",
	sprintf("%d of %d overrides carry a WeightedCapacity; Auto Scaling needs a weight on all of them or on none, and the group create fails with \"Not all instance types have a defined WeightedCapacity\"", [w, n]),
	"Weight every override, or remove every weight", _pf_asgowu_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	n := count(_pf_aslib_overrides(name))
	w := _pf_asgowu_weighted(name)
	w > 0
	w < n
}
