package cdk_preflight

import rego.v1

# SourceKafkaClusterArn addresses an MSK cluster, SourceKafkaClusterId a
# self-managed Apache Kafka cluster. Both in one ReplicationInfo is rejected.
violation contains make_diag_full("pf-msk-replicator-source-arn-xor-id", "ERROR", name,
	sprintf("Properties.ReplicationInfoList[%d]", [it.index]),
	"the entry carries both SourceKafkaClusterArn and SourceKafkaClusterId; the replicator create fails with \"Cannot specify both sourceKafkaClusterArn and sourceKafkaClusterId\"",
	"Use SourceKafkaClusterArn for an MSK source, SourceKafkaClusterId for an Apache Kafka source",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-replicator-replicationinfo.html") if {
	some name in resources_of_type("AWS::MSK::Replicator")
	some it in flatten_list(name, "Properties.ReplicationInfoList")
	is_object(it.value)
	object.get(it.value, "SourceKafkaClusterArn", null) != null
	object.get(it.value, "SourceKafkaClusterId", null) != null
}
