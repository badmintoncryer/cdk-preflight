package cdk_preflight

import rego.v1

# The .kraft Apache Kafka versions drop the smallest Standard broker: CreateClusterV2 answers
# "Unsupported InstanceType specified. Valid values: [...]" with a list that holds every other
# broker size but not kafka.t3.small. The same instance type is perfectly valid on 3.9.x, so no
# layer that looks at either property alone can see this.
violation contains make_diag_full("pf-msk-t3-small-not-kraft", "ERROR", name,
	"Properties.BrokerNodeGroupInfo.InstanceType",
	sprintf("kafka.t3.small with Apache Kafka %s; the create fails with \"Unsupported InstanceType specified\" because KRaft mode has no t3 broker", [v]),
	"Move to kafka.m5.large or larger, or pick a ZooKeeper-mode version such as 3.9.x",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-cluster-brokernodegroupinfo.html") if {
	some name in resources_of_type("AWS::MSK::Cluster")
	resolve(name, "Properties.BrokerNodeGroupInfo.InstanceType") == "kafka.t3.small"
	v := resolve(name, "Properties.KafkaVersion")
	is_string(v)
	endswith(v, ".kraft")
}
