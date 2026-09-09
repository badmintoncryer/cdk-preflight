package cdk_preflight

import rego.v1

_pf_asgstat_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-step-requires-adjustmenttype", "ERROR", name,
	"Properties.AdjustmentType",
	"a StepScaling policy has no AdjustmentType; the policy create fails with \"You must specify an AdjustmentType for policy type: StepScaling\"",
	"Set AdjustmentType to ChangeInCapacity, ExactCapacity or PercentChangeInCapacity", _pf_asgstat_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	_pf_aslib_ptype(name) == "StepScaling"
	_pf_aslib_absent(name, "AdjustmentType")
}
