package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-set-requires-element", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("%v in namespace %v is a Set with no element type; CreatePolicyStore answers \"missing field `element`\"", [p, nsname]),
	"Give the Set an element, e.g. {\"type\": \"Set\", \"element\": {\"type\": \"String\"}}",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, nsname, p, t] in _pf_avpsch_types
	object.get(t, "type", null) == "Set"
	object.get(t, "element", "__pf_absent") == "__pf_absent"
}
