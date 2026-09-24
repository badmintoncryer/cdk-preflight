package cdk_preflight

import rego.v1

_pf_aoss_lifert_fix := "Set ResourceType to index and write every Resource as index/<collection>/<index>, with * allowed in either segment"

violation contains make_diag_full("pf-aoss-lifecycle-resource-type", "ERROR", name,
	sprintf("%v.ResourceType", [p]),
	sprintf("ResourceType is %v; CreateLifecyclePolicy answers \"Policy json is invalid, error: [$.Rules[0].ResourceType: must be a constant value index]\"", [rt]),
	_pf_aoss_lifert_fix, "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-lifecycle.html") if {
	some name in _pf_aoss_life
	some [p, r] in _pf_aoss_rules_at(name)
	rt := object.get(r, "ResourceType", null)
	is_string(rt)
	rt != "index"
}

violation contains make_diag_full("pf-aoss-lifecycle-resource-type", "ERROR", name,
	sprintf("%v.Resource", [p]),
	sprintf("Resource %v is not an index pattern; CreateLifecyclePolicy answers \"Policy json is invalid, error: [$.Rules[0].Resource[0]: does not match the regex pattern ^index/...\"", [res]),
	_pf_aoss_lifert_fix, "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-lifecycle.html") if {
	some name in _pf_aoss_life
	some [p, r] in _pf_aoss_rules_at(name)
	some res in _pf_aoss_strings(object.get(r, "Resource", []))
	not regex.match(_pf_aoss_re_index_life, res)
}
