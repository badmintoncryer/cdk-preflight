package cdk_preflight

import rego.v1

# The other half of the pair: HonorMaxCapacity says the forecast may never go
# past MaxCapacity, so a buffer above it would have nothing to describe. Only
# the spelled-out behaviour is judged — the default is the same value, but the
# probe that produced this message set it explicitly, and so must the rule.
violation contains make_diag_full("pf-appautoscaling-predictive-buffer-forbidden", "ERROR", name,
	"Properties.PredictiveScalingPolicyConfiguration.MaxCapacityBuffer",
	"MaxCapacityBreachBehavior is HonorMaxCapacity, which leaves MaxCapacityBuffer nothing to do; PutScalingPolicy fails with \"You cannot specify MaxCapacityBuffer when using HonorMaxCapacity.\"",
	"Drop MaxCapacityBuffer, or switch MaxCapacityBreachBehavior to IncreaseMaxCapacity",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PredictiveScalingPolicyConfiguration.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	cfg := object.get(_pf_aaslib_props(name), "PredictiveScalingPolicyConfiguration", "__pf_absent")
	is_object(cfg)
	object.get(cfg, "MaxCapacityBreachBehavior", "__pf_absent") == "HonorMaxCapacity"
	object.get(cfg, "MaxCapacityBuffer", "__pf_absent") != "__pf_absent"
}
