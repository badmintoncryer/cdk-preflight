package cdk_preflight

import rego.v1

# data.cdk_preflight.deploy_account is injected only in enforce mode with a
# concrete account; the rule stays silent otherwise. Covers both principal
# shapes - IAM/STS ARNs and saml/<account>/<config>/user|group/<name> - which
# the service rejects with one and the same message.

violation contains make_diag_full("pf-aoss-access-policy-principal-account", "ERROR", name,
	sprintf("%v.Principal", [p]),
	sprintf("principal %v belongs to account %v but the policy deploys to %v; CreateAccessPolicy answers \"Cross account principal(s) are not allowed in policy. Please update the policy and retry\"", [princ, a, acct]),
	"Name a principal in the account the policy deploys into; cross-account access needs its own data access policy in the other account",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-data-access.html") if {
	some name in _pf_aoss_data
	acct := data.cdk_preflight.deploy_account
	is_string(acct)
	some [p, b] in _pf_aoss_blocks_at(name)
	some princ in _pf_aoss_strings(object.get(b, "Principal", []))
	a := _pf_aoss_principal_account(princ)
	a != acct
}
