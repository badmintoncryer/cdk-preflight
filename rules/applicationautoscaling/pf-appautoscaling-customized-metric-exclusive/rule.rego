package cdk_preflight

import rego.v1

# "You can use a specification with metric math or a specification without
# metric math, but not a combination of both." Metrics[] is the metric-math
# form; MetricName / Namespace / Statistic / Dimensions / Unit are the single
# metric form.
_pf_aascme_spec(name) := s if {
	p := input.resources[name].properties
	c := object.get(p, "TargetTrackingScalingPolicyConfiguration", {})
	s := object.get(c, "CustomizedMetricSpecification", "__pf_absent")
	is_object(s)
}

violation contains make_diag_full("pf-appautoscaling-customized-metric-exclusive", "ERROR", name,
	"Properties.TargetTrackingScalingPolicyConfiguration.CustomizedMetricSpecification",
	sprintf("CustomizedMetricSpecification carries the metric math Metrics array and also %s; PutScalingPolicy fails with \"The customized metric specification is not valid.\"", [concat(", ", sort(extra))]),
	"Keep Metrics for metric math, or MetricName/Namespace/Statistic for a single metric",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_CustomizedMetricSpecification.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	s := _pf_aascme_spec(name)
	is_array(object.get(s, "Metrics", "__pf_absent"))
	extra := {k |
		some k in {"MetricName", "Namespace", "Statistic", "Dimensions", "Unit"}
		object.get(s, k, "__pf_absent") != "__pf_absent"
	}
	count(extra) > 0
}
