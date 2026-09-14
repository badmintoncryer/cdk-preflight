package cdk_preflight

import rego.v1

# ENHANCED offset sync tracks the same topic name on both sides, so it is
# only accepted when TopicNameConfiguration.Type is IDENTICAL. The rule judges
# an explicitly declared Type only - whether the documented default
# (PREFIXED_WITH_SOURCE_CLUSTER_ALIAS) is rejected the same way is unmeasured.
violation contains make_diag_full("pf-msk-replicator-enhanced-sync-requires-identical", "ERROR", name,
	sprintf("Properties.ReplicationInfoList[%d].ConsumerGroupReplication.ConsumerGroupOffsetSyncMode", [it.index]),
	sprintf("ConsumerGroupOffsetSyncMode ENHANCED is combined with TopicNameConfiguration.Type '%s'; the replicator create fails with \"The consumerGroupOffsetSyncMode value ENHANCED is only supported when topicNameConfiguration type is IDENTICAL\"", [t]),
	"Set TopicNameConfiguration.Type to IDENTICAL, or use the LEGACY offset sync mode",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-replicator.html") if {
	some name in resources_of_type("AWS::MSK::Replicator")
	some it in flatten_list(name, "Properties.ReplicationInfoList")
	is_object(it.value)
	object.get(it.value, ["ConsumerGroupReplication", "ConsumerGroupOffsetSyncMode"], null) == "ENHANCED"
	t := object.get(it.value, ["TopicReplication", "TopicNameConfiguration", "Type"], null)
	is_string(t)
	t != "IDENTICAL"
}
