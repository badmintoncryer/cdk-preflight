package cdk_preflight

import rego.v1

_pf_asgpcm_url := "https://docs.aws.amazon.com/autoscaling/ec2/APIReference/API_PutScalingPolicy.html"

_pf_asgpcm_has(s, key) if object.get(s, key, "__pf_absent") != "__pf_absent"

_pf_asgpcm_scaling(s) if _pf_asgpcm_has(s, "PredefinedScalingMetricSpecification")

_pf_asgpcm_scaling(s) if _pf_asgpcm_has(s, "CustomizedScalingMetricSpecification")

violation contains make_diag_full("pf-asg-predictive-capacity-metric-requires-load-and-scaling", "ERROR", name,
	sprintf("Properties.PredictiveScalingConfiguration.MetricSpecifications.%d.CustomizedLoadMetricSpecification", [i]),
	"a customized capacity metric is set but the load metric is not a customized one; the capacity metric only refines a customized load metric, and the policy create fails with \"Capacity metric can only be used when you use customized load metric.\"",
	"Add CustomizedLoadMetricSpecification, or drop CustomizedCapacityMetricSpecification", _pf_asgpcm_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	some i, s in _pf_aslib_pmetrics(name)
	is_object(s)
	_pf_asgpcm_has(s, "CustomizedCapacityMetricSpecification")
	not _pf_asgpcm_has(s, "CustomizedLoadMetricSpecification")
}

violation contains make_diag_full("pf-asg-predictive-capacity-metric-requires-load-and-scaling", "ERROR", name,
	sprintf("Properties.PredictiveScalingConfiguration.MetricSpecifications.%d.CustomizedScalingMetricSpecification", [i]),
	"a customized capacity metric is set but no scaling metric is; the capacity metric only refines a load metric plus a scaling metric, and the policy create fails with \"A policy must have either one scaling metric and one load metric or one metric pair\"",
	"Add a scaling metric, or drop CustomizedCapacityMetricSpecification", _pf_asgpcm_url) if {
	some name in resources_of_type("AWS::AutoScaling::ScalingPolicy")
	some i, s in _pf_aslib_pmetrics(name)
	is_object(s)
	_pf_asgpcm_has(s, "CustomizedCapacityMetricSpecification")
	not _pf_asgpcm_scaling(s)
}
