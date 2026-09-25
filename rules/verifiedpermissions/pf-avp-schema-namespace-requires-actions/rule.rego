package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-namespace-requires-actions", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("namespace %v declares no actions; CreatePolicyStore answers \"missing field `actions`\"", [nsname]),
	"Give the namespace an actions object, empty if it declares no actions",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, nsname, def] in _pf_avpsch_ns
	object.get(def, "actions", "__pf_absent") == "__pf_absent"
}
