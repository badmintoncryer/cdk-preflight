package cdk_preflight

import rego.v1

_pf_aasttm_cfg(name) := c if {
	p := input.resources[name].properties
	c := object.get(p, "TargetTrackingScalingPolicyConfiguration", "__pf_absent")
	is_object(c)
}

violation contains make_diag_full("pf-appautoscaling-tt-metric-spec-missing", "ERROR", name,
	"Properties.TargetTrackingScalingPolicyConfiguration",
	"Neither PredefinedMetricSpecification nor CustomizedMetricSpecification is set; PutScalingPolicy fails with \"PredefinedMetricSpecification or CustomizedMetricSpecification must be set for target tracking scaling.\"",
	"Add the metric the policy should track",
	"https://docs.aws.amazon.com/autoscaling/application/userguide/target-tracking-scaling-policy-overview.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	c := _pf_aasttm_cfg(name)
	object.get(c, "PredefinedMetricSpecification", "__pf_absent") == "__pf_absent"
	object.get(c, "CustomizedMetricSpecification", "__pf_absent") == "__pf_absent"
}
