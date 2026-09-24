package cdk_preflight

import rego.v1

_pf_aasarl_spec(name) := s if {
	p := input.resources[name].properties
	c := object.get(p, "TargetTrackingScalingPolicyConfiguration", {})
	s := object.get(c, "PredefinedMetricSpecification", "__pf_absent")
	is_object(s)
}

violation contains make_diag_full("pf-appautoscaling-alb-metric-requires-resource-label", "ERROR", name,
	"Properties.TargetTrackingScalingPolicyConfiguration.PredefinedMetricSpecification.ResourceLabel",
	"PredefinedMetricType ALBRequestCountPerTarget has no ResourceLabel; PutScalingPolicy fails with \"Resource label should be specified for predefined metric type ALBRequestCountPerTarget\"",
	"Add ResourceLabel as app/<lb-name>/<lb-id>/targetgroup/<tg-name>/<tg-id>",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PredefinedMetricSpecification.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	s := _pf_aasarl_spec(name)
	object.get(s, "PredefinedMetricType", "__pf_absent") == "ALBRequestCountPerTarget"
	object.get(s, "ResourceLabel", "__pf_absent") == "__pf_absent"
}
