package cdk_preflight

import rego.v1

_pf_asgsfo_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgsfo_forbidden := ["MetricAggregationType", "EstimatedInstanceWarmup", "StepAdjustments", "TargetTrackingConfiguration"]

violation contains make_diag_full("pf-asg-simple-forbids-other-policy-props", "ERROR", name,
	sprintf("Properties.%s", [k]),
	sprintf("%s belongs to a step or target-tracking policy, not to SimpleScaling; the policy create fails with \"%s is not supported for a SimpleScaling policy\"", [k, k]),
	sprintf("Remove %s, or change PolicyType to the one that owns it", [k]), _pf_asgsfo_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	_pf_aslib_ptype(name) == "SimpleScaling"
	some k in _pf_asgsfo_forbidden
	not _pf_aslib_absent(name, k)
}
