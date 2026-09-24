package cdk_preflight

import rego.v1

# "Scalable dimension <dim> only supports the following predefined metric types:
# <list>". The key is the ScalableDimension, not the ServiceNamespace, which is
# why a DynamoDB read dimension refuses the write metric of its own namespace.
# The allowed sets are the namespace's own metric types from the API reference,
# narrowed only where the bench measured a narrower answer (the DynamoDB read /
# write split) — a set that is too wide can only miss, never misfire.
# elasticmapreduce and custom-resource are absent: they have no predefined
# metric type at all, so there is nothing to compare a value against.
_pf_aaspmd_allowed := {
	"appstream:fleet:DesiredCapacity": {
		"AppStreamAverageCapacityUtilization",
	},
	"cassandra:table:ReadCapacityUnits": {
		"CassandraReadCapacityUtilization", "CassandraWriteCapacityUtilization",
	},
	"cassandra:table:WriteCapacityUnits": {
		"CassandraReadCapacityUtilization", "CassandraWriteCapacityUtilization",
	},
	"comprehend:document-classifier-endpoint:DesiredInferenceUnits": {
		"ComprehendInferenceUtilization",
	},
	"comprehend:entity-recognizer-endpoint:DesiredInferenceUnits": {
		"ComprehendInferenceUtilization",
	},
	"dynamodb:index:ReadCapacityUnits": {
		"DynamoDBReadCapacityUtilization", "DynamoDBWriteCapacityUtilization",
	},
	"dynamodb:index:WriteCapacityUnits": {
		"DynamoDBReadCapacityUtilization", "DynamoDBWriteCapacityUtilization",
	},
	"dynamodb:table:ReadCapacityUnits": {
		"DynamoDBReadCapacityUtilization",
	},
	"dynamodb:table:WriteCapacityUnits": {
		"DynamoDBWriteCapacityUtilization",
	},
	"ec2:spot-fleet-request:TargetCapacity": {
		"ALBRequestCountPerTarget", "EC2SpotFleetRequestAverageCPUUtilization",
		"EC2SpotFleetRequestAverageNetworkIn", "EC2SpotFleetRequestAverageNetworkOut",
	},
	"ecs:service:DesiredCount": {
		"ALBRequestCountPerTarget", "ECSServiceAverageCPUUtilization",
		"ECSServiceAverageCPUUtilizationHighResolution", "ECSServiceAverageMemoryUtilization",
		"ECSServiceAverageMemoryUtilizationHighResolution",
	},
	"elasticache:cache-cluster:Nodes": {
		"ElastiCacheDatabaseCapacityUsageCountedForEvictPercentage",
		"ElastiCacheDatabaseMemoryUsageCountedForEvictPercentage",
		"ElastiCacheDatabaseMemoryUsagePercentage", "ElastiCacheEngineCPUUtilization",
		"ElastiCachePrimaryEngineCPUUtilization", "ElastiCacheReplicaEngineCPUUtilization",
	},
	"elasticache:replication-group:NodeGroups": {
		"ElastiCacheDatabaseCapacityUsageCountedForEvictPercentage",
		"ElastiCacheDatabaseMemoryUsageCountedForEvictPercentage",
		"ElastiCacheDatabaseMemoryUsagePercentage", "ElastiCacheEngineCPUUtilization",
		"ElastiCachePrimaryEngineCPUUtilization", "ElastiCacheReplicaEngineCPUUtilization",
	},
	"elasticache:replication-group:Replicas": {
		"ElastiCacheDatabaseCapacityUsageCountedForEvictPercentage",
		"ElastiCacheDatabaseMemoryUsageCountedForEvictPercentage",
		"ElastiCacheDatabaseMemoryUsagePercentage", "ElastiCacheEngineCPUUtilization",
		"ElastiCachePrimaryEngineCPUUtilization", "ElastiCacheReplicaEngineCPUUtilization",
	},
	"kafka:broker-storage:VolumeSize": {
		"KafkaBrokerStorageUtilization",
	},
	"lambda:function:ProvisionedConcurrency": {
		"LambdaProvisionedConcurrencyUtilization",
	},
	"neptune:cluster:ReadReplicaCount": {
		"NeptuneReaderAverageCPUUtilization",
	},
	"rds:cluster:ReadReplicaCount": {
		"RDSReaderAverageCPUUtilization", "RDSReaderAverageDatabaseConnections",
	},
	"sagemaker:inference-component:DesiredCopyCount": {
		"SageMakerInferenceComponentConcurrentRequestsPerCopyHighResolution",
		"SageMakerInferenceComponentInvocationsPerCopy",
		"SageMakerVariantConcurrentRequestsPerModelHighResolution",
		"SageMakerVariantInvocationsPerInstance", "SageMakerVariantProvisionedConcurrencyUtilization",
	},
	"sagemaker:variant:DesiredInstanceCount": {
		"SageMakerInferenceComponentConcurrentRequestsPerCopyHighResolution",
		"SageMakerInferenceComponentInvocationsPerCopy",
		"SageMakerVariantConcurrentRequestsPerModelHighResolution",
		"SageMakerVariantInvocationsPerInstance", "SageMakerVariantProvisionedConcurrencyUtilization",
	},
	"sagemaker:variant:DesiredProvisionedConcurrency": {
		"SageMakerInferenceComponentConcurrentRequestsPerCopyHighResolution",
		"SageMakerInferenceComponentInvocationsPerCopy",
		"SageMakerVariantConcurrentRequestsPerModelHighResolution",
		"SageMakerVariantInvocationsPerInstance", "SageMakerVariantProvisionedConcurrencyUtilization",
	},
	"workspaces:workspacespool:DesiredUserSessions": {
		"WorkSpacesAverageUserSessionsCapacityUtilization",
	},
}

# Literal guard: a Ref resolves to a logical id, which is never a metric type.
_pf_aaspmd_known := {
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

violation contains make_diag_full("pf-appautoscaling-predefined-metric-dimension", "ERROR", name,
	"Properties.TargetTrackingScalingPolicyConfiguration.PredefinedMetricSpecification.PredefinedMetricType",
	sprintf("PredefinedMetricType '%s' is not available on scalable dimension '%s'; PutScalingPolicy fails with \"Scalable dimension %s only supports the following predefined metric types: %s\"", [mt, dim, dim, concat(", ", sort(allowed))]),
	"Pick a predefined metric type the scalable dimension supports",
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PredefinedMetricSpecification.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalingPolicy")
	mt := resolve(name, "Properties.TargetTrackingScalingPolicyConfiguration.PredefinedMetricSpecification.PredefinedMetricType")
	mt in _pf_aaspmd_known
	dim := _pf_aaslib_dimension(name)
	allowed := _pf_aaspmd_allowed[dim]
	not mt in allowed
}
