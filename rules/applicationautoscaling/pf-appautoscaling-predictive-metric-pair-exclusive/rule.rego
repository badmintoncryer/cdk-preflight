package cdk_preflight

import rego.v1

# PredictiveScalingMetricSpecification has six metric members — a predefined
# pair, and predefined/customized load and scaling metrics — and the service
# accepts exactly two shapes: the pair on its own, or one load metric together
# with one scaling metric, in either flavour. Everything else, a bare scaling
# metric and an entry with no metric at all included, draws the same sentence.
# CustomizedCapacityMetricSpecification is an optional extra and not counted.
_pf_aaspme_load := {"CustomizedLoadMetricSpecification", "PredefinedLoadMetricSpecification"}

_pf_aaspme_scaling := {"CustomizedScalingMetricSpecification", "PredefinedScalingMetricSpecification"}

_pf_aaspme_n(spec, keys) := count([k |
	some k in keys
	object.get(spec, k, "__pf_absent") != "__pf_absent"
])

_pf_aaspme_ok(spec) if {
	object.get(spec, "PredefinedMetricPairSpecification", "__pf_absent") != "__pf_absent"
	_pf_aaspme_n(spec, _pf_aaspme_load) == 0
	_pf_aaspme_n(spec, _pf_aaspme_scaling) == 0
}

_pf_aaspme_ok(spec) if {
	object.get(spec, "PredefinedMetricPairSpecification", "__pf_absent") == "__pf_absent"
	_pf_aaspme_n(spec, _pf_aaspme_load) == 1
	_pf_aaspme_n(spec, _pf_aaspme_scaling) == 1
}

violation contains make_diag_full("pf-appautoscaling-predictive-metric-pair-exclusive", "ERROR", name,
	sprintf("Properties.PredictiveScalingPolicyConfiguration.MetricSpecifications.%d", [m.index]),
	"This metric specification is neither a lone metric pair nor one scaling metric with one load metric; PutScalingPolicy fails with \"The metric specification is invalid. A policy must have either one scaling metric and one load metric or one metric pair.\"",
	"Use PredefinedMetricPairSpecification on its own, or pair a scaling metric with a load metric",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PredictiveScalingMetricSpecification.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	some m in flatten_list(name, "Properties.PredictiveScalingPolicyConfiguration.MetricSpecifications")
	is_object(m.value)
	not _pf_aaspme_ok(m.value)
}
