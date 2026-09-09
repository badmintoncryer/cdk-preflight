package cdk_preflight

import rego.v1

_pf_asgttsp_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgttsp_periods(name) := {p |
	some q in _pf_aslib_arr(name, ["TargetTrackingConfiguration", "CustomizedMetricSpecification", "Metrics"])
	is_object(q)
	st := object.get(q, "MetricStat", null)
	is_object(st)
	v := object.get(st, "Period", null)
	v != null
	not is_object(v)
	p := to_number(v)
}

violation contains make_diag_full("pf-asg-tt-mq-same-period-required", "ERROR", name,
	"Properties.TargetTrackingConfiguration.CustomizedMetricSpecification.Metrics",
	sprintf("the metric data queries use %d different periods; CloudWatch needs one period per alarm and the policy create fails with \"All metrics in the alarm should have the same period\"", [count(ps)]),
	"Give every MetricStat the same Period", _pf_asgttsp_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	ps := _pf_asgttsp_periods(name)
	count(ps) > 1
}
