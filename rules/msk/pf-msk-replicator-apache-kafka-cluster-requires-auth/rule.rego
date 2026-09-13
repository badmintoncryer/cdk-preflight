package cdk_preflight

import rego.v1

# A self-managed Apache Kafka source has no MSK-side auth to inherit, so the
# entry has to spell out how the replicator authenticates to it.
violation contains make_diag_full("pf-msk-replicator-apache-kafka-cluster-requires-auth", "ERROR", name,
	sprintf("Properties.KafkaClusters[%d]", [it.index]),
	"an ApacheKafkaCluster entry has no ClientAuthentication; the replicator create fails with \"Apache Kafka clusters require authentication configuration. Specify the clientAuthentication parameter.\"",
	"Add ClientAuthentication (and EncryptionInTransit) to the Apache Kafka cluster entry",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-replicator-kafkacluster.html") if {
	some name in resources_of_type("AWS::MSK::Replicator")
	some it in flatten_list(name, "Properties.KafkaClusters")
	is_object(it.value)
	object.get(it.value, "ApacheKafkaCluster", null) != null
	object.get(it.value, "AmazonMskCluster", null) == null
	object.get(it.value, "ClientAuthentication", null) == null
}
