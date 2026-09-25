package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-shape-must-be-record", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("entity type %v::%v has a shape of type %v; CreatePolicyStore answers \"Shape for entity type %v::%v is declared with a type other than `Record`\"", [nsname, t, ty, nsname, t]),
	"Declare the shape as {\"type\": \"Record\", \"attributes\": {...}}",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, nsname, t, d] in _pf_avpsch_ets
	sh := object.get(d, "shape", null)
	is_object(sh)
	ty := object.get(sh, "type", null)
	ty in {"String", "Long", "Boolean", "Set", "Entity", "Extension"}
}
