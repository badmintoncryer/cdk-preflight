package cdk_preflight

import rego.v1

# json.unmarshal is undefined for text that is not JSON, so the one negation
# covers both halves of the constraint: not JSON at all, and JSON that is not
# an object (an array, a string, a number).
_pf_avpsvj_object(s) if is_object(json.unmarshal(s))
violation contains make_diag_full("pf-avp-schema-valid-json-object", "ERROR", name, "Properties.Schema.CedarJson",
	"Schema.CedarJson is not a JSON object; CreatePolicyStore answers \"Provided schema is not a valid JSON object\"",
	"Write the Cedar schema as a JSON object of namespace name to namespace body, e.g. {\"MyApp\": {\"entityTypes\": {}, \"actions\": {}}}",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, s] in _pf_avpsch_stores
	not _pf_avpsvj_object(s)
}
