package cdk_preflight

import rego.v1

# The ResourceId is "<resource type><separator><identifier>" and the resource
# type is fixed by the ScalableDimension's middle segment: a DynamoDB table is
# table/my-table, an Aurora cluster is cluster:my-db-cluster (a colon, not a
# slash), MSK and Comprehend take a full ARN. A bare name or the wrong separator
# is rejected with "Unsupported service namespace, resource type or scalable
# dimension". custom-resource is deliberately absent: its identifier is defined
# by the resource provider and has no fixed shape.
_pf_aasrid_prefix := {
	"ecs:service:DesiredCount": "service/",
	"ec2:spot-fleet-request:TargetCapacity": "spot-fleet-request/",
	"elasticmapreduce:instancegroup:InstanceCount": "instancegroup/",
	"appstream:fleet:DesiredCapacity": "fleet/",
	"dynamodb:table:ReadCapacityUnits": "table/",
	"dynamodb:table:WriteCapacityUnits": "table/",
	"dynamodb:index:ReadCapacityUnits": "table/",
	"dynamodb:index:WriteCapacityUnits": "table/",
	"rds:cluster:ReadReplicaCount": "cluster:",
	"sagemaker:variant:DesiredInstanceCount": "endpoint/",
	"sagemaker:variant:DesiredProvisionedConcurrency": "endpoint/",
	"sagemaker:inference-component:DesiredCopyCount": "inference-component/",
	"comprehend:document-classifier-endpoint:DesiredInferenceUnits": "arn:",
	"comprehend:entity-recognizer-endpoint:DesiredInferenceUnits": "arn:",
	"lambda:function:ProvisionedConcurrency": "function:",
	"cassandra:table:ReadCapacityUnits": "keyspace/",
	"cassandra:table:WriteCapacityUnits": "keyspace/",
	"kafka:broker-storage:VolumeSize": "arn:",
	"elasticache:cache-cluster:Nodes": "cache-cluster/",
	"elasticache:replication-group:NodeGroups": "replication-group/",
	"elasticache:replication-group:Replicas": "replication-group/",
	"neptune:cluster:ReadReplicaCount": "cluster:",
	"workspaces:workspacespool:DesiredUserSessions": "workspacespool/",
}

violation contains make_diag_full("pf-appautoscaling-resource-id-shape", "ERROR", name,
	"Properties.ResourceId",
	sprintf("ResourceId '%s' does not start with '%s', which is the resource type ScalableDimension '%s' names; RegisterScalableTarget fails with \"Unsupported service namespace, resource type or scalable dimension\"", [rid, want, dim]),
	sprintf("Prefix the identifier with '%s' (see the ResourceId examples in the RegisterScalableTarget reference)", [want]),
	"https://docs.aws.amazon.com/autoscaling/application/APIReference/API_RegisterScalableTarget.html") if {
	some name in resources_of_type("AWS::ApplicationAutoScaling::ScalableTarget")
	dim := resolve(name, "Properties.ScalableDimension")
	want := _pf_aasrid_prefix[dim]
	rid := resolve(name, "Properties.ResourceId")
	is_string(rid)
	not input.resources[rid]
	not startswith(rid, want)
}
