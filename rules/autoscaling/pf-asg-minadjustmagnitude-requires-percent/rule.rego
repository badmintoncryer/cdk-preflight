package cdk_preflight

import rego.v1

_pf_asgmrp_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-minadjustmagnitude-requires-percent", "ERROR", name,
	"Properties.MinAdjustmentMagnitude",
	sprintf("MinAdjustmentMagnitude is set while AdjustmentType is %s; it only applies to PercentChangeInCapacity and the policy create fails with \"MinAdjustmentMagnitude is not supported by the specified adjustment type\"", [t]),
	"Drop MinAdjustmentMagnitude, or switch AdjustmentType to PercentChangeInCapacity", _pf_asgmrp_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	not _pf_aslib_absent(name, "MinAdjustmentMagnitude")
	t := resolve(name, "Properties.AdjustmentType")
	_pf_aslib_lit(t)
	t != "PercentChangeInCapacity"
}
