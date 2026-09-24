package cdk_preflight

import rego.v1

_pf_aastte_cfg(name) := c if {
	p := input.resources[name].properties
	c := object.get(p, "TargetTrackingScalingPolicyConfiguration", "__pf_absent")
	is_object(c)
}

violation contains make_diag_full("pf-appautoscaling-tt-metric-spec-exclusive", "ERROR", name,
	"Properties.TargetTrackingScalingPolicyConfiguration",
	"Both PredefinedMetricSpecification and CustomizedMetricSpecification are set; PutScalingPolicy fails with \"Only one of PredefinedMetricSpecification or CustomizedMetricSpecification can be set for target tracking scaling.\"",
	"Keep the one metric the policy should track and delete the other",
	"https://docs.aws.amazon.com/autoscaling/application/userguide/target-tracking-scaling-policy-overview.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	c := _pf_aastte_cfg(name)
	is_object(object.get(c, "PredefinedMetricSpecification", "__pf_absent"))
	is_object(object.get(c, "CustomizedMetricSpecification", "__pf_absent"))
}
