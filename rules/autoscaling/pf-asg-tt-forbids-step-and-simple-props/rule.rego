package cdk_preflight

import rego.v1

_pf_asgttfo_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgttfo_forbidden := ["MetricAggregationType", "MinAdjustmentMagnitude", "ScalingAdjustment", "StepAdjustments", "PredictiveScalingConfiguration"]

violation contains make_diag_full("pf-asg-tt-forbids-step-and-simple-props", "ERROR", name,
	sprintf("Properties.%s", [k]),
	sprintf("%s belongs to another policy type, not to TargetTrackingScaling; the policy create fails with \"%s are not supported for a TargetTracking policy\"", [k, k]),
	sprintf("Remove %s; a target-tracking policy scales from TargetValue alone", [k]), _pf_asgttfo_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	_pf_aslib_ptype(name) == "TargetTrackingScaling"
	some k in _pf_asgttfo_forbidden
	not _pf_aslib_absent(name, k)
}
