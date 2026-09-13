package cdk_preflight

import rego.v1

# VpcConfig describes how the replicator reaches an MSK cluster. An entry that
# describes a self-managed Apache Kafka cluster must not carry one.
# An entry with both cluster kinds is pf-msk-replicator-kafka-cluster-exactly-one-kind's
# business, so this rule stays out of it.
violation contains make_diag_full("pf-msk-replicator-vpc-config-only-for-msk-cluster", "ERROR", name,
	sprintf("Properties.KafkaClusters[%d].VpcConfig", [it.index]),
	"an ApacheKafkaCluster entry carries VpcConfig; the replicator create fails with \"The vpcConfig parameter is only supported for AmazonMskCluster\"",
	"Drop VpcConfig from the Apache Kafka cluster entry",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-replicator-kafkacluster.html") if {
	some name in resources_of_type("AWS::MSK::Replicator")
	some it in flatten_list(name, "Properties.KafkaClusters")
	is_object(it.value)
	object.get(it.value, "ApacheKafkaCluster", null) != null
	object.get(it.value, "AmazonMskCluster", null) == null
	object.get(it.value, "VpcConfig", null) != null
}
