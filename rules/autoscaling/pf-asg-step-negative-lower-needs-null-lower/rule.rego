package cdk_preflight

import rego.v1

_pf_asgstnn_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgstnn_negative(name) if {
	some s in _pf_aslib_steps(name)
	is_object(s)
	object.get(s, "MetricIntervalLowerBound", null) != null
	_pf_aslib_step_lo(s) < 0
}

violation contains make_diag_full("pf-asg-step-negative-lower-needs-null-lower", "ERROR", name,
	"Properties.StepAdjustments",
	"a step starts below the alarm threshold but no step leaves MetricIntervalLowerBound unset; the policy create fails with \"There must be a StepAdjustment with an unspecified lower bound ... when one StepAdjustment has a negative lower bound\"",
	"Add a bottom step with no MetricIntervalLowerBound", _pf_asgstnn_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	_pf_asgstnn_negative(name)
	_pf_aslib_step_nulls(name, "MetricIntervalLowerBound") == 0
}
