package cdk_preflight

import rego.v1

# BatchAssociateScramSecret only accepts secrets owned by the cluster's account; a foreign-account
# secret ARN is rejected with "The provided secret ARN is invalid. ... InvalidParameter:
# secretArnList" before the cluster is even looked up.
# The comparison is between the two ARNs written in the template, never against
# data.cdk_preflight.deploy_account -- fixtures and real apps both use literal bench-account ARNs.
_pf_msksa_acct(arn) := a if {
	is_string(arn)
	parts := split(arn, ":")
	count(parts) >= 6
	parts[0] == "arn"
	a := parts[4]
	a != ""
}

violation contains make_diag_full("pf-msk-scram-secret-account", "ERROR", name,
	"Properties.SecretArnList",
	sprintf("secret '%s' is in account %s but the cluster is in account %s; the association fails with \"The provided secret ARN is invalid\"", [sarn, sacct, cacct]),
	"Create the SCRAM secret in the same account as the cluster",
	"https://docs.aws.amazon.com/msk/latest/developerguide/msk-password-tutorial.html") if {
	some name in resources_of_type("AWS::MSK::BatchScramSecret")
	cacct := _pf_msksa_acct(resolve(name, "Properties.ClusterArn"))
	some it in flatten_list(name, "Properties.SecretArnList")
	sarn := it.value
	startswith(sarn, "arn:")
	sacct := _pf_msksa_acct(sarn)
	sacct != cacct
}
