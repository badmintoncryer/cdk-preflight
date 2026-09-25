package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aoss-access-policy-resource-type-prefix", "ERROR", name,
	sprintf("%v.Resource", [p]),
	sprintf("ResourceType is %v but Resource %v starts with %v/; CreateAccessPolicy answers \"Policy json is invalid, error: [$[0].Rules[0].Resource[0]: does not match the regex pattern ^%v/...\"", [rt, res, seg, rt]),
	"Split the rule: a collection/ resource belongs in a ResourceType collection rule, an index/ resource in a ResourceType index rule",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-data-access.html") if {
	some name in _pf_aoss_data
	some [p, r] in _pf_aoss_rules_at(name)
	rt := object.get(r, "ResourceType", null)
	rt in object.keys(_pf_aoss_perms)
	some res in _pf_aoss_strings(object.get(r, "Resource", []))
	seg := split(res, "/")[0]
	seg != rt
}
