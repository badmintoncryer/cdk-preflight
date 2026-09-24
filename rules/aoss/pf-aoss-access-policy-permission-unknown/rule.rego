package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aoss-access-policy-permission-unknown", "ERROR", name,
	sprintf("%v.Permission", [p]),
	sprintf("%v is not an OpenSearch Serverless data access permission; CreateAccessPolicy answers \"Policy json is invalid, error: [$[0].Rules[0].Permission[0]: does not have a value in the enumeration [...]]\"", [perm]),
	"Data access policies take aoss: actions only - IAM actions such as es:* or aoss:CreateCollection do not belong here",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-genref.html") if {
	some name in _pf_aoss_data
	some [p, r] in _pf_aoss_rules_at(name)
	rt := object.get(r, "ResourceType", null)
	rt in object.keys(_pf_aoss_perms)
	some perm in _pf_aoss_strings(object.get(r, "Permission", []))
	not perm in _pf_aoss_all_perms
}
