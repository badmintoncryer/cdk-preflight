package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-aoss-access-policy-index-resource-segments", "ERROR", name,
	sprintf("%v.Resource", [p]),
	sprintf("index resource %v is not index/<collection>/<index>; CreateAccessPolicy answers \"Policy json is invalid, error: [$[0].Rules[0].Resource[0]: does not match the regex pattern ^index/(?:[a-z][a-z0-9_-]{2,63}\\*?|\\*)/...\"", [res]),
	"Name both segments, e.g. index/my-collection/* or index/my-collection/logs-*",
	"https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-data-access.html") if {
	some name in _pf_aoss_data
	some [p, r] in _pf_aoss_rules_at(name)
	object.get(r, "ResourceType", null) == "index"
	some res in _pf_aoss_strings(object.get(r, "Resource", []))
	startswith(res, "index/")
	not regex.match(_pf_aoss_re_index_data, res)
}
