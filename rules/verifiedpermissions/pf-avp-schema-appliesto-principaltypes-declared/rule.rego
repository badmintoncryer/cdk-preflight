package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-appliesto-principaltypes-declared", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("action %v::%v applies to principal type %v, which the schema does not declare; CreatePolicyStore answers \"failed to resolve type: %v\"", [nsname, a, ref, ref]),
	"Declare the principal entity type, or qualify the reference with the namespace that declares it",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, nsname, a, d] in _pf_avpsch_acts
	ap := object.get(d, "appliesTo", {})
	is_object(ap)
	pts := object.get(ap, "principalTypes", [])
	is_array(pts)
	some ref in pts
	is_string(ref)
	not [name, nsname, ref] in _pf_avpsch_etnames
}
