package cdk_preflight

import rego.v1

# The replicator, its ServiceExecutionRoleArn and its clusters all live in one
# account: CreateReplicator refuses to pass a role from another account. The
# check is against the cluster ARNs rather than deploy_account so that it also
# fires in region/account-agnostic apps, where deploy_account is not injected.
_pf_mskrsr_account(arn, service) := acct if {
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	parts[2] == service
	acct := parts[4]
	acct != ""
}

_pf_mskrsr_clusters(name) := accounts if {
	accounts := {a |
		some it in flatten_list(name, "Properties.KafkaClusters")
		a := _pf_mskrsr_account(it.value.AmazonMskCluster.MskClusterArn, "kafka")
	}
}

violation contains make_diag_full("pf-msk-replicator-service-role-account", "ERROR", name,
	"Properties.ServiceExecutionRoleArn",
	sprintf("the service execution role is in account %s while the clusters are in %s; the replicator create fails with \"Cross-account pass role is not allowed.\"", [roleAcct, clusterAcct]),
	"Use a role from the account that owns the clusters and the replicator",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-msk-replicator.html") if {
	some name in resources_of_type("AWS::MSK::Replicator")
	roleAcct := _pf_mskrsr_account(resolve(name, "Properties.ServiceExecutionRoleArn"), "iam")
	accounts := _pf_mskrsr_clusters(name)
	count(accounts) == 1
	some clusterAcct in accounts
	roleAcct != clusterAcct
}
