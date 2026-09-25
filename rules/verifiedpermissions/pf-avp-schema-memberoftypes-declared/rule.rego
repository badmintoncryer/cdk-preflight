package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-memberoftypes-declared", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("entity type %v::%v is a member of %v, which the schema does not declare; CreatePolicyStore answers \"failed to resolve type: %v\"", [nsname, t, ref, ref]),
	"Declare the parent entity type, or qualify the reference with the namespace that declares it",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, nsname, t, d] in _pf_avpsch_ets
	mot := object.get(d, "memberOfTypes", [])
	is_array(mot)
	some ref in mot
	is_string(ref)
	not [name, nsname, ref] in _pf_avpsch_etnames
}
