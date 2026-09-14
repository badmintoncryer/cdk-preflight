package cdk_preflight

import rego.v1

# One entry describes one cluster: AmazonMskCluster for an MSK cluster,
# ApacheKafkaCluster for a self-managed one. Both together is rejected.
violation contains make_diag_full("pf-msk-replicator-kafka-cluster-exactly-one-kind", "ERROR", name,
	sprintf("Properties.KafkaClusters[%d]", [it.index]),
	"the entry carries both AmazonMskCluster and ApacheKafkaCluster; the replicator create fails with \"Cannot specify both AmazonMskCluster and ApacheKafkaCluster in a kafkaCluster object\"",
	"Keep one cluster kind per KafkaClusters entry",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-replicator-kafkacluster.html") if {
	some name in resources_of_type("AWS::MSK::Replicator")
	some it in flatten_list(name, "Properties.KafkaClusters")
	is_object(it.value)
	object.get(it.value, "AmazonMskCluster", null) != null
	object.get(it.value, "ApacheKafkaCluster", null) != null
}
