package cdk_preflight

import rego.v1

_pf_asgstfo_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgstfo_forbidden := ["ScalingAdjustment", "TargetTrackingConfiguration"]

violation contains make_diag_full("pf-asg-step-forbids-other-policy-props", "ERROR", name,
	sprintf("Properties.%s", [k]),
	sprintf("%s belongs to a simple or target-tracking policy, not to StepScaling; the policy create fails with \"%s is not supported for a StepScaling policy\"", [k, k]),
	sprintf("Remove %s; a step policy scales through StepAdjustments", [k]), _pf_asgstfo_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	_pf_aslib_ptype(name) == "StepScaling"
	some k in _pf_asgstfo_forbidden
	not _pf_aslib_absent(name, k)
}
