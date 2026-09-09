package cdk_preflight

import rego.v1

_pf_asgxcn_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-exactcapacity-nonnegative", "ERROR", name,
	"Properties.ScalingAdjustment",
	sprintf("ScalingAdjustment %v is negative while AdjustmentType is ExactCapacity, which sets the capacity outright; the policy create fails with \"The lower range for adjustment is 0 with the specified adjustment type\"", [n]),
	"Use a ScalingAdjustment of 0 or more, or switch to ChangeInCapacity", _pf_asgxcn_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	resolve(name, "Properties.AdjustmentType") == "ExactCapacity"
	n := _pf_aslib_num(name, "Properties.ScalingAdjustment")
	n < 0
}
