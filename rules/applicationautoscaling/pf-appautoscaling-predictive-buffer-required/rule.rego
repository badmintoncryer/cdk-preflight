package cdk_preflight

import rego.v1

# MaxCapacityBreachBehavior IncreaseMaxCapacity lets the forecast push capacity
# past MaxCapacity, and MaxCapacityBuffer is how far — the service will not
# guess it.
violation contains make_diag_full("pf-appautoscaling-predictive-buffer-required", "ERROR", name,
	"Properties.PredictiveScalingPolicyConfiguration.MaxCapacityBuffer",
	"MaxCapacityBreachBehavior is IncreaseMaxCapacity but no MaxCapacityBuffer is set; PutScalingPolicy fails with \"You must specify MaxCapacityBuffer when using IncreaseMaxCapacity.\"",
	"Set MaxCapacityBuffer to the percentage of MaxCapacity the forecast may exceed, or use MaxCapacityBreachBehavior HonorMaxCapacity",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PredictiveScalingPolicyConfiguration.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	cfg := object.get(_pf_aaslib_props(name), "PredictiveScalingPolicyConfiguration", "__pf_absent")
	is_object(cfg)
	object.get(cfg, "MaxCapacityBreachBehavior", "__pf_absent") == "IncreaseMaxCapacity"
	object.get(cfg, "MaxCapacityBuffer", "__pf_absent") == "__pf_absent"
}
