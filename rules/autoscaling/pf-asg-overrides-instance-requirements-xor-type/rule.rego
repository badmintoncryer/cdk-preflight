package cdk_preflight

import rego.v1

_pf_asgoix_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-overrides-instance-requirements-xor-type", "ERROR", name,
	sprintf("Properties.MixedInstancesPolicy.LaunchTemplate.Overrides.%d.InstanceType", [i]),
	"the override sets both InstanceType and InstanceRequirements; the group create fails with \"The parameter InstanceType cannot be used in a launch template override using instance requirements\"",
	"Keep either InstanceType or InstanceRequirements in each override", _pf_asgoix_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	some i, o in _pf_aslib_overrides(name)
	is_object(o)
	is_object(object.get(o, "InstanceRequirements", null))
	object.get(o, "InstanceType", "__pf_absent") != "__pf_absent"
}
