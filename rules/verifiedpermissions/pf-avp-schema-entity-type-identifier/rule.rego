package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-entity-type-identifier", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("entity type %v in namespace %v is not a Cedar identifier; CreatePolicyStore answers \"invalid id `%v`\"", [t, nsname, t]),
	"Spell the entity type name with letters, digits and underscores only, e.g. MyType",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, nsname, t, _] in _pf_avpsch_ets
	not regex.match(`^[A-Za-z_][A-Za-z_0-9]*$`, t)
}
