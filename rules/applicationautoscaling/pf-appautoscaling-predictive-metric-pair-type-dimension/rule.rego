package cdk_preflight

import rego.v1

# CloudFormation's schema knows the nine PredefinedMetricPairSpecification
# values but not which of them a scalable dimension accepts. ecs:service:
# DesiredCount takes three: "The predefined metric pair type for scalable
# dimension ecs:service:DesiredCount isn't valid. The supported values are:
# ECSServiceMemoryUtilization, ALBRequestCount and ECSServiceCPUUtilization."
# Only the ECS dimension is listed because predictive scaling is only offered
# on ECS at all, which pf-appautoscaling-predictive-scaling-ecs-only covers.
_pf_aasppt_ecs := {"ALBRequestCount", "ECSServiceCPUUtilization", "ECSServiceMemoryUtilization"}

_pf_aasppt_known := {
	"ALBRequestCount", "ALBRequestCountPerTarget", "ECSServiceAverageCPUUtilization",
	"ECSServiceAverageMemoryUtilization", "ECSServiceCPUUtilization",
	"ECSServiceMemoryUtilization", "ECSServiceTotalCPUUtilization",
	"ECSServiceTotalMemoryUtilization", "TotalALBRequestCount",
}

violation contains make_diag_full("pf-appautoscaling-predictive-metric-pair-type-dimension", "ERROR", name,
	sprintf("Properties.PredictiveScalingPolicyConfiguration.MetricSpecifications.%d.PredefinedMetricPairSpecification.PredefinedMetricType", [m.index]),
	sprintf("Predefined metric pair type '%s' is not one an ECS service accepts; PutScalingPolicy fails with \"The predefined metric pair type for scalable dimension ecs:service:DesiredCount isn't valid.\"", [mt]),
	"Use ECSServiceCPUUtilization, ECSServiceMemoryUtilization or ALBRequestCount",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PredictiveScalingMetricSpecification.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	_pf_aaslib_dimension(name) == "ecs:service:DesiredCount"
	some m in flatten_list(name, "Properties.PredictiveScalingPolicyConfiguration.MetricSpecifications")
	mt := object.get(object.get(m.value, "PredefinedMetricPairSpecification", {}), "PredefinedMetricType", "__pf_absent")
	mt in _pf_aasppt_known
	not mt in _pf_aasppt_ecs
}
