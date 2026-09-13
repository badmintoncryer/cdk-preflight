package cdk_preflight

import rego.v1

# KafkaClusters carries the source and the target; naming the same cluster
# twice (a copy-paste of the ARN) is rejected outright.
_pf_mskrstd_arns(name) := arns if {
	arns := [a |
		some it in flatten_list(name, "Properties.KafkaClusters")
		a := it.value.AmazonMskCluster.MskClusterArn
		is_string(a)
	]
}

violation contains make_diag_full("pf-msk-replicator-source-target-differ", "ERROR", name,
	"Properties.KafkaClusters",
	sprintf("KafkaClusters lists %d cluster ARNs but only %d distinct one(s); the replicator create fails with \"Kafka cluster list contains duplicate cluster ARNs\"", [count(arns), count(uniq)]),
	"Point the source and the target at two different MSK clusters",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-replicator.html") if {
	some name in resources_of_type("AWS::MSK::Replicator")
	arns := _pf_mskrstd_arns(name)
	count(arns) > 1
	uniq := {a | some a in arns}
	count(uniq) < count(arns)
}
