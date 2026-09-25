package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-namespace-requires-entitytypes", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("namespace %v declares no entityTypes; CreatePolicyStore answers \"missing field `entityTypes`\"", [nsname]),
	"Give the namespace an entityTypes object, empty if it declares no entity types",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, nsname, def] in _pf_avpsch_ns
	object.get(def, "entityTypes", "__pf_absent") == "__pf_absent"
}
