package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-attribute-type-known", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("%v in namespace %v has type %v, which is neither a Cedar built-in nor a type the schema declares; CreatePolicyStore answers \"failed to resolve type: %v\"", [p, nsname, ty, ty]),
	"Use String, Long, Boolean, Record, Set, Entity, Extension or EntityOrCommon, or declare the type under commonTypes",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, nsname, p, t] in _pf_avpsch_types
	ty := object.get(t, "type", null)
	is_string(ty)
	not ty in _pf_avpsch_builtin
	not [name, nsname, ty] in _pf_avpsch_ctnames
	not [name, nsname, ty] in _pf_avpsch_etnames
}
