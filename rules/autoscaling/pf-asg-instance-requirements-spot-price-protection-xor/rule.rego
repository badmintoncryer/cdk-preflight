package cdk_preflight

import rego.v1

_pf_asgirsp_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_CreateAutoScalingGroup.html"

violation contains make_diag_full("pf-asg-instance-requirements-spot-price-protection-xor", "ERROR", name,
	sprintf("Properties.MixedInstancesPolicy.LaunchTemplate.Overrides.%d.InstanceRequirements.MaxSpotPriceAsPercentageOfOptimalOnDemandPrice", [i]),
	"the instance requirements set both SpotMaxPricePercentageOverLowestPrice and MaxSpotPriceAsPercentageOfOptimalOnDemandPrice; the group create fails with \"Specify only one of these parameters\"",
	"Keep one spot price protection baseline", _pf_asgirsp_url) if {
	some name in resources_of_type("AWS::AutoScaling::AutoScalingGroup")
	some i, o in _pf_aslib_overrides(name)
	is_object(o)
	ir := object.get(o, "InstanceRequirements", null)
	is_object(ir)
	object.get(ir, "SpotMaxPricePercentageOverLowestPrice", "__pf_absent") != "__pf_absent"
	object.get(ir, "MaxSpotPriceAsPercentageOfOptimalOnDemandPrice", "__pf_absent") != "__pf_absent"
}
