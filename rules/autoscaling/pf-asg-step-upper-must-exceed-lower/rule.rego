package cdk_preflight

import rego.v1

_pf_asgstul_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-step-upper-must-exceed-lower", "ERROR", name,
	sprintf("Properties.StepAdjustments.%d.MetricIntervalUpperBound", [i]),
	sprintf("the step runs from %v to %v; the upper bound has to be strictly above the lower bound and the policy create fails with \"LowerBound must be less than the UpperBound for StepAdjustment\"", [lo, hi]),
	"Raise MetricIntervalUpperBound above MetricIntervalLowerBound", _pf_asgstul_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	some i, s in _pf_aslib_steps(name)
	is_object(s)
	object.get(s, "MetricIntervalLowerBound", null) != null
	object.get(s, "MetricIntervalUpperBound", null) != null
	lo := _pf_aslib_step_lo(s)
	hi := _pf_aslib_step_hi(s)
	hi <= lo
}
