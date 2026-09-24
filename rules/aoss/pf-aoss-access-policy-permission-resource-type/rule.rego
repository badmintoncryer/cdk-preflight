package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aoss-access-policy-permission-resource-type", "ERROR", name,
	sprintf("%v.Permission", [p]),
	sprintf("%v is not a %v permission; CreateAccessPolicy answers \"Policy json is invalid, error: [$[0].Rules[0].Permission[0]: does not have a value in the enumeration [...]]\"", [perm, rt]),
	"Move the permission into a rule whose ResourceType owns it (collection / index / model / agent), or use aoss:*",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-data-access.html") if {
	some name in _pf_aoss_data
	some [p, r] in _pf_aoss_rules_at(name)
	rt := object.get(r, "ResourceType", null)
	rt in object.keys(_pf_aoss_perms)
	some perm in _pf_aoss_strings(object.get(r, "Permission", []))
	perm in _pf_aoss_all_perms
	not perm in _pf_aoss_perms[rt]
}
