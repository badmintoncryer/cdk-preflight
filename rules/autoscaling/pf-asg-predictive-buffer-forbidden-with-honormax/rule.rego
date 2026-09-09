package cdk_preflight

import rego.v1

_pf_asgpbh_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgpbh_behavior(name) := b if {
	b := resolve(name, "Properties.PredictiveScalingConfiguration.MaxCapacityBreachBehavior")
	_pf_aslib_lit(b)
}

_pf_asgpbh_behavior(name) := "HonorMaxCapacity" if _pf_aslib_absent_at(name, ["PredictiveScalingConfiguration", "MaxCapacityBreachBehavior"])

violation contains make_diag_full("pf-asg-predictive-buffer-forbidden-with-honormax", "ERROR", name,
	"Properties.PredictiveScalingConfiguration.MaxCapacityBuffer",
	"MaxCapacityBuffer is set while MaxCapacityBreachBehavior is HonorMaxCapacity (its default), so the buffer has nothing to grow into; the policy create fails with \"You must not specify max capacity buffer when using HonorMaxCapacity\"",
	"Remove MaxCapacityBuffer, or set MaxCapacityBreachBehavior to IncreaseMaxCapacity", _pf_asgpbh_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	not _pf_aslib_absent_at(name, ["PredictiveScalingConfiguration", "MaxCapacityBuffer"])
	_pf_asgpbh_behavior(name) == "HonorMaxCapacity"
}
