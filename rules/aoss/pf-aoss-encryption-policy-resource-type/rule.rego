package cdk_preflight

import rego.v1

_pf_aoss_encrt_fix := "Set ResourceType to collection and write every Resource as collection/<name>, collection/<prefix>* or collection/*"

violation contains make_diag_full("pf-aoss-encryption-policy-resource-type", "ERROR", name,
	sprintf("%v.ResourceType", [p]),
	sprintf("ResourceType is %v; CreateSecurityPolicy answers \"Policy json is invalid, error: [$.Rules[0].ResourceType: must be a constant value collection]\"", [rt]),
	_pf_aoss_encrt_fix, "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-encryption.html") if {
	some name in _pf_aoss_enc
	some [p, r] in _pf_aoss_rules_at(name)
	rt := object.get(r, "ResourceType", null)
	is_string(rt)
	rt != "collection"
}

violation contains make_diag_full("pf-aoss-encryption-policy-resource-type", "ERROR", name,
	sprintf("%v.Resource", [p]),
	sprintf("Resource %v is not a collection pattern; CreateSecurityPolicy answers \"Policy json is invalid, error: [$.Rules[0].Resource[0]: does not match the regex pattern ^collection/...\"", [res]),
	_pf_aoss_encrt_fix, "https://docs.aws.amazon.com/opensearch-service/latest/developerguide/serverless-encryption.html") if {
	some name in _pf_aoss_enc
	some [p, r] in _pf_aoss_rules_at(name)
	some res in _pf_aoss_strings(object.get(r, "Resource", []))
	not regex.match(_pf_aoss_re_collection, res)
}
