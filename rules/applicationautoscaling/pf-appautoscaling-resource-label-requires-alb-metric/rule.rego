package cdk_preflight

import rego.v1

_pf_aasrla_spec(name) := s if {
	p := input.resources[name].properties
	c := object.get(p, "TargetTrackingScalingPolicyConfiguration", {})
	s := object.get(c, "PredefinedMetricSpecification", "__pf_absent")
	is_object(s)
}

violation contains make_diag_full("pf-appautoscaling-resource-label-requires-alb-metric", "ERROR", name,
	"Properties.TargetTrackingScalingPolicyConfiguration.PredefinedMetricSpecification.ResourceLabel",
	sprintf("ResourceLabel is set alongside PredefinedMetricType '%s'; PutScalingPolicy fails with \"Resource label should not be specified for predefined metric type %s\"", [mt, mt]),
	"Delete ResourceLabel, or switch the metric type to ALBRequestCountPerTarget",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PredefinedMetricSpecification.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	s := _pf_aasrla_spec(name)
	mt := object.get(s, "PredefinedMetricType", "__pf_absent")
	mt in _pf_aaspmd_known_rla
	mt != "ALBRequestCountPerTarget"
	object.get(s, "ResourceLabel", "__pf_absent") != "__pf_absent"
}

_pf_aaspmd_known_rla := {
	"ALBRequestCountPerTarget", "AppStreamAverageCapacityUtilization",
	"CassandraReadCapacityUtilization", "CassandraWriteCapacityUtilization",
	"ComprehendInferenceUtilization", "DynamoDBReadCapacityUtilization",
	"DynamoDBWriteCapacityUtilization", "EC2SpotFleetRequestAverageCPUUtilization",
	"EC2SpotFleetRequestAverageNetworkIn", "EC2SpotFleetRequestAverageNetworkOut",
	"ECSServiceAverageCPUUtilization", "ECSServiceAverageCPUUtilizationHighResolution",
	"ECSServiceAverageMemoryUtilization", "ECSServiceAverageMemoryUtilizationHighResolution",
	"ElastiCacheDatabaseCapacityUsageCountedForEvictPercentage",
	"ElastiCacheDatabaseMemoryUsageCountedForEvictPercentage",
	"ElastiCacheDatabaseMemoryUsagePercentage", "ElastiCacheEngineCPUUtilization",
	"ElastiCachePrimaryEngineCPUUtilization", "ElastiCacheReplicaEngineCPUUtilization",
	"KafkaBrokerStorageUtilization", "LambdaProvisionedConcurrencyUtilization",
	"NeptuneReaderAverageCPUUtilization", "RDSReaderAverageCPUUtilization",
	"RDSReaderAverageDatabaseConnections",
	"SageMakerInferenceComponentConcurrentRequestsPerCopyHighResolution",
	"SageMakerInferenceComponentInvocationsPerCopy",
	"SageMakerVariantConcurrentRequestsPerModelHighResolution",
	"SageMakerVariantInvocationsPerInstance", "SageMakerVariantProvisionedConcurrencyUtilization",
	"WorkSpacesAverageUserSessionsCapacityUtilization",
}
