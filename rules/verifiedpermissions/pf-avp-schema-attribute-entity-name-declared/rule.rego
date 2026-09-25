package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-attribute-entity-name-declared", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("%v in namespace %v is an Entity of type %v, which the schema does not declare; CreatePolicyStore answers \"failed to resolve type: %v\"", [p, nsname, n, n]),
	"Declare the entity type, or qualify the name with the namespace that declares it",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, nsname, p, t] in _pf_avpsch_types
	object.get(t, "type", null) == "Entity"
	n := object.get(t, "name", null)
	is_string(n)
	not [name, nsname, n] in _pf_avpsch_etnames
}
