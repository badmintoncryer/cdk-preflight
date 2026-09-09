package cdk_preflight

import rego.v1

_pf_asgstxc_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-step-exactcapacity-nonnegative", "ERROR", name,
	sprintf("Properties.StepAdjustments.%d.ScalingAdjustment", [i]),
	sprintf("step ScalingAdjustment %v is negative while AdjustmentType is ExactCapacity, which sets the capacity outright; the policy create fails with \"The lowest value for ScalingAdjustment parameter is 0 with the specified adjustment type\"", [n]),
	"Use 0 or more in every step, or switch to ChangeInCapacity", _pf_asgstxc_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	resolve(name, "Properties.AdjustmentType") == "ExactCapacity"
	some i, s in _pf_aslib_steps(name)
	is_object(s)
	v := object.get(s, "ScalingAdjustment", null)
	v != null
	not is_object(v)
	n := to_number(v)
	n < 0
}
