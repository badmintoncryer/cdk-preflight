package cdk_preflight

import rego.v1

_pf_asgmam_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-minadjustmagnitude-positive", "ERROR", name,
	"Properties.MinAdjustmentMagnitude",
	sprintf("MinAdjustmentMagnitude %v is not greater than zero; the policy create fails with \"If specified, MinAdjustmentMagnitude must be greater than zero\"", [n]),
	"Use 1 or more, or leave MinAdjustmentMagnitude out", _pf_asgmam_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	n := _pf_aslib_num(name, "Properties.MinAdjustmentMagnitude")
	n <= 0
}
