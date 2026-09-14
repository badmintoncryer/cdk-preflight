package cdk_preflight

import rego.v1

# MSK Replicator does not replicate across accounts: both cluster ARNs must
# carry the same account id. The deploy-time failure never names the rule --
# the service simply cannot read the other account's cluster.
_pf_mskrsa_account(e) := acct if {
	arn := e.AmazonMskCluster.MskClusterArn
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == "kafka"
	acct := parts[4]
	acct != ""
}

violation contains make_diag_full("pf-msk-replicator-clusters-same-account", "ERROR", name,
	"Properties.KafkaClusters",
	sprintf("the cluster ARNs name %d different accounts (%s); the replicator create fails with an AccessDenied on kafka:GetBootstrapBrokers against the other account's cluster", [count(accounts), joined]),
	"Replicate between clusters in one account - MSK Replicator does not support cross-account replication",
	"https://docs.aws.amazon.com/msk/latest/developerguide/msk-replicator-supported-configs.html") if {
	some name in resources_of_type("AWS::MSK::Replicator")
	accounts := {a |
		some it in flatten_list(name, "Properties.KafkaClusters")
		a := _pf_mskrsa_account(it.value)
	}
	count(accounts) > 1
	joined := concat(", ", sort(accounts))
}
