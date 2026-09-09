package cdk_preflight

import rego.v1

_pf_asgttmx_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgttmx_queries(name) := _pf_aslib_arr(name, ["TargetTrackingConfiguration", "CustomizedMetricSpecification", "Metrics"])

_pf_asgttmx_has(q, k) if object.get(q, k, "__pf_absent") != "__pf_absent"

violation contains make_diag_full("pf-asg-tt-mq-expression-xor-metricstat", "ERROR", name,
	sprintf("Properties.TargetTrackingConfiguration.CustomizedMetricSpecification.Metrics.%d", [i]),
	"the metric data query sets both Expression and MetricStat; the policy create fails with \"The parameters MetricDataQuery Expression and MetricStat are mutually exclusive and you have specified both\"",
	"Keep either Expression or MetricStat in each query", _pf_asgttmx_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	some i, q in _pf_asgttmx_queries(name)
	is_object(q)
	_pf_asgttmx_has(q, "Expression")
	_pf_asgttmx_has(q, "MetricStat")
}

violation contains make_diag_full("pf-asg-tt-mq-expression-xor-metricstat", "ERROR", name,
	sprintf("Properties.TargetTrackingConfiguration.CustomizedMetricSpecification.Metrics.%d", [i]),
	"the metric data query sets neither Expression nor MetricStat; the policy create fails with \"The parameters MetricDataQuery Expression and MetricStat are mutually exclusive\"",
	"Give each query either an Expression or a MetricStat", _pf_asgttmx_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	some i, q in _pf_asgttmx_queries(name)
	is_object(q)
	not _pf_asgttmx_has(q, "Expression")
	not _pf_asgttmx_has(q, "MetricStat")
}
