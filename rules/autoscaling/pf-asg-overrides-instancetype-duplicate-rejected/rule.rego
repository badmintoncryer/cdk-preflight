package cdk_preflight

import rego.v1

_pf_asgoid_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-overrides-instancetype-duplicate-rejected", "ERROR", name,
	sprintf("Properties.MixedInstancesPolicy.LaunchTemplate.Overrides.%d.InstanceType", [j]),
	sprintf("instance type %s is overridden twice; the group create fails with \"Cannot add same instance type override more than once\"", [v]),
	"Keep one override per instance type", _pf_asgoid_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	ovs := _pf_aslib_overrides(name)
	some i, a in ovs
	some j, b in ovs
	i < j
	is_object(a)
	is_object(b)
	v := object.get(a, "InstanceType", null)
	_pf_aslib_lit(v)
	object.get(b, "InstanceType", null) == v
}
