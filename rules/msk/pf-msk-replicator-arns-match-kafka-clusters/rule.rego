package cdk_preflight

import rego.v1

# ReplicationInfoList repeats the ARNs that KafkaClusters declares. A third
# ARN (or a typo in one of the two) is rejected at create time.
# The rule only judges when every AmazonMskCluster entry handed over a literal
# ARN - a Ref / GetAtt wired cluster surfaces as a marker object and is skipped.
_pf_mskram_arns(name) := arns if {
	arns := {a |
		some it in flatten_list(name, "Properties.KafkaClusters")
		a := it.value.AmazonMskCluster.MskClusterArn
		is_string(a)
	}
}

_pf_mskram_msk_entries(name) := n if {
	n := count([1 |
		some it in flatten_list(name, "Properties.KafkaClusters")
		is_object(it.value)
		object.get(it.value, "AmazonMskCluster", null) != null
	])
}

violation contains make_diag_full("pf-msk-replicator-arns-match-kafka-clusters", "ERROR", name,
	sprintf("Properties.ReplicationInfoList[%d].%s", [it.index, key]),
	sprintf("%s '%s' is not one of the cluster ARNs in KafkaClusters; the replicator create fails with \"Source and target Kafka cluster ARNs must be present in kafkaClusters\"", [key, arn]),
	"Repeat the KafkaClusters ARNs verbatim in ReplicationInfoList",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-properties-msk-replicator-replicationinfo.html") if {
	some name in resources_of_type("AWS::MSK::Replicator")
	arns := _pf_mskram_arns(name)
	count(arns) > 0
	count(arns) == _pf_mskram_msk_entries(name)
	some it in flatten_list(name, "Properties.ReplicationInfoList")
	is_object(it.value)
	some key in ["SourceKafkaClusterArn", "TargetKafkaClusterArn"]
	arn := object.get(it.value, key, null)
	is_string(arn)
	not arn in arns
}
