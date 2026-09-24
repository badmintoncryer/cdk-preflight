package cdk_preflight

import rego.v1

# The label is the tail of the load balancer ARN and the tail of the target
# group ARN joined with a slash. PutScalingPolicy checks the shape before it
# checks that the target group is attached, so a malformed label fails the stack
# with "Invalid resource label '<value>' for predefined metric type
# ALBRequestCountPerTarget" and never reaches the load balancer.
_pf_aasrlf_spec(name) := s if {
	p := input.resources[name].properties
	c := object.get(p, "TargetTrackingScalingPolicyConfiguration", {})
	s := object.get(c, "PredefinedMetricSpecification", "__pf_absent")
	is_object(s)
}

violation contains make_diag_full("pf-appautoscaling-resource-label-format", "ERROR", name,
	"Properties.TargetTrackingScalingPolicyConfiguration.PredefinedMetricSpecification.ResourceLabel",
	sprintf("ResourceLabel '%s' is not app/<lb-name>/<lb-id>/targetgroup/<tg-name>/<tg-id>; PutScalingPolicy fails with \"Invalid resource label\"", [rl]),
	"Join the tail of the load balancer ARN and the tail of the target group ARN with a slash",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PredefinedMetricSpecification.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	rl := object.get(_pf_aasrlf_spec(name), "ResourceLabel", null)
	is_string(rl)
	not input.resources[rl]
	not regex.match(`^app/[^/]+/[^/]+/targetgroup/[^/]+/[^/]+$`, rl)
}
