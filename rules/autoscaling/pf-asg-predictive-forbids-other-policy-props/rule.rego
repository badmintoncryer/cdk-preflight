package cdk_preflight

import rego.v1

_pf_asgpfo_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgpfo_forbidden := ["TargetTrackingConfiguration", "AdjustmentType", "ScalingAdjustment", "StepAdjustments", "EstimatedInstanceWarmup"]

violation contains make_diag_full("pf-asg-predictive-forbids-other-policy-props", "ERROR", name,
	sprintf("Properties.%s", [k]),
	sprintf("%s belongs to another policy type, not to PredictiveScaling; the policy create fails with \"You can't specify %s for policy type: PredictiveScaling\"", [k, k]),
	sprintf("Remove %s; predictive scaling is driven by PredictiveScalingConfiguration alone", [k]), _pf_asgpfo_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	_pf_aslib_ptype(name) == "PredictiveScaling"
	some k in _pf_asgpfo_forbidden
	not _pf_aslib_absent(name, k)
}
