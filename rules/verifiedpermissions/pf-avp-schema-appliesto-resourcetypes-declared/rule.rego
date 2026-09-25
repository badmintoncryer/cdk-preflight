package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-appliesto-resourcetypes-declared", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("action %v::%v applies to resource type %v, which the schema does not declare; CreatePolicyStore answers \"failed to resolve type: %v\"", [nsname, a, ref, ref]),
	"Declare the resource entity type, or qualify the reference with the namespace that declares it",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, nsname, a, d] in _pf_avpsch_acts
	ap := object.get(d, "appliesTo", {})
	is_object(ap)
	rts := object.get(ap, "resourceTypes", [])
	is_array(rts)
	some ref in rts
	is_string(ref)
	not [name, nsname, ref] in _pf_avpsch_etnames
}
