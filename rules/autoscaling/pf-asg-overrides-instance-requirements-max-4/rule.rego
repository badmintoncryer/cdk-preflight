package cdk_preflight

import rego.v1

_pf_asgoim_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

_pf_asgoim_count(name) := count([1 |
	some o in _pf_aslib_overrides(name)
	is_object(o)
	is_object(object.get(o, "InstanceRequirements", null))
])

violation contains make_diag_full("pf-asg-overrides-instance-requirements-max-4", "ERROR", name,
	"Properties.MixedInstancesPolicy.LaunchTemplate.Overrides",
	sprintf("%d overrides use InstanceRequirements; at most 4 may, and the group create fails with \"You can only have 4 launch template overrides using instance requirements at most\"", [n]),
	"Merge the requirement sets so at most four remain", _pf_asgoim_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	n := _pf_asgoim_count(name)
	n > 4
}
