package cdk_preflight

import rego.v1

_pf_asgstpu_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgstpu_positive(name) if {
	some s in _pf_aslib_steps(name)
	is_object(s)
	object.get(s, "MetricIntervalUpperBound", null) != null
	_pf_aslib_step_hi(s) > 0
}

violation contains make_diag_full("pf-asg-step-positive-upper-needs-null-upper", "ERROR", name,
	"Properties.StepAdjustments",
	"a step ends above the alarm threshold but no step leaves MetricIntervalUpperBound unset; the policy create fails with \"There must be a StepAdjustment with an unspecified upper bound ... when one StepAdjustment has a positive upper bound\"",
	"Add a top step with no MetricIntervalUpperBound", _pf_asgstpu_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	_pf_asgstpu_positive(name)
	_pf_aslib_step_nulls(name, "MetricIntervalUpperBound") == 0
}
