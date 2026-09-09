package cdk_preflight

import rego.v1

_pf_asgstnu_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

violation contains make_diag_full("pf-asg-step-multiple-null-upper", "ERROR", name,
	"Properties.StepAdjustments",
	sprintf("%d steps leave MetricIntervalUpperBound unset; only the top step may, and the policy create fails with \"At most one StepAdjustment may have an unspecified upper bound\"", [n]),
	"Give every step but the top one an explicit MetricIntervalUpperBound", _pf_asgstnu_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	n := _pf_aslib_step_nulls(name, "MetricIntervalUpperBound")
	n > 1
}
