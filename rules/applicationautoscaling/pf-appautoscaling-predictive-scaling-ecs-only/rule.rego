package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-appautoscaling-predictive-scaling-ecs-only", "ERROR", name,
	"Properties.PolicyType",
	sprintf("PolicyType PredictiveScaling is only supported for ecs, but this policy scales the '%s' namespace; PutScalingPolicy rejects it", [ns]),
	"Use TargetTrackingScaling or StepScaling outside ecs",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PutScalingPolicy.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	resolve(name, "Properties.PolicyType") == "PredictiveScaling"
	ns := _pf_aaslib_namespace(name)
	ns != "ecs"
}
