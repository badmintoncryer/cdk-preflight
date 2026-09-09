package cdk_preflight

import rego.v1

_pf_asgwpwm_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutWarmPool.html"

violation contains make_diag_full("pf-asg-wp-weighted-mixed-instances-incompatible", "ERROR", name,
	sprintf("Properties.MixedInstancesPolicy.LaunchTemplate.Overrides.%d.WeightedCapacity", [i]),
	sprintf("group %s weights its instance types, so the warm pool create fails with \"You can't add a warm pool to an Auto Scaling group that ... uses a mixed instances policy with ... instance weights\"", [g]),
	"Drop WeightedCapacity from the overrides, or drop the warm pool", _pf_asgwpwm_url) if {
	some name in resources_of_type("AWS::AutoScaling::WarmPool")
	g := _pf_aslib_group(name)
	some i, o in _pf_aslib_overrides(g)
	is_object(o)
	object.get(o, "WeightedCapacity", "__pf_absent") != "__pf_absent"
}
