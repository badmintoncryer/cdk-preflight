package cdk_preflight

import rego.v1

_pf_asgstnl_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-step-multiple-null-lower", "ERROR", name,
	"Properties.StepAdjustments",
	sprintf("%d steps leave MetricIntervalLowerBound unset; only the bottom step may, and the policy create fails with \"At most one StepAdjustment may have an unspecified lower bound\"", [n]),
	"Give every step but the bottom one an explicit MetricIntervalLowerBound", _pf_asgstnl_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	n := _pf_aslib_step_nulls(name, "MetricIntervalLowerBound")
	n > 1
}
