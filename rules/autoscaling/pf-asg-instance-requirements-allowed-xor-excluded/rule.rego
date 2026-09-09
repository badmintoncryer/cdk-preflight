package cdk_preflight

import rego.v1

_pf_asgirax_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-instance-requirements-allowed-xor-excluded", "ERROR", name,
	sprintf("Properties.MixedInstancesPolicy.LaunchTemplate.Overrides.%d.InstanceRequirements.ExcludedInstanceTypes", [i]),
	"the instance requirements set both AllowedInstanceTypes and ExcludedInstanceTypes; the group create fails with \"You can specify either AllowedInstanceTypes or ExcludedInstanceTypes, but not both\"",
	"Keep one of the two lists", _pf_asgirax_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	some i, o in _pf_aslib_overrides(name)
	is_object(o)
	ir := object.get(o, "InstanceRequirements", null)
	is_object(ir)
	object.get(ir, "AllowedInstanceTypes", "__pf_absent") != "__pf_absent"
	object.get(ir, "ExcludedInstanceTypes", "__pf_absent") != "__pf_absent"
}
