package cdk_preflight

import rego.v1

_pf_asgppx_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgppx_pair := ["PredefinedMetricPairSpecification", "CustomizedMetricPairSpecification"]

_pf_asgppx_indiv := [
	"PredefinedLoadMetricSpecification", "CustomizedLoadMetricSpecification",
	"PredefinedScalingMetricSpecification", "CustomizedScalingMetricSpecification",
]

_pf_asgppx_hasany(s, keys) if {
	some k in keys
	object.get(s, k, "__pf_absent") != "__pf_absent"
}

violation contains make_diag_full("pf-asg-predictive-metric-pair-xor-individual", "ERROR", name,
	sprintf("Properties.PredictiveScalingConfiguration.MetricSpecifications.%d", [i]),
	"the metric specification carries a metric pair and an individual load or scaling metric; the policy create fails with \"A policy must have either one scaling metric and one load metric or one metric pair\"",
	"Keep the metric pair on its own, or drop it and give a load metric plus a scaling metric", _pf_asgppx_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	some i, s in _pf_aslib_pmetrics(name)
	is_object(s)
	_pf_asgppx_hasany(s, _pf_asgppx_pair)
	_pf_asgppx_hasany(s, _pf_asgppx_indiv)
}
