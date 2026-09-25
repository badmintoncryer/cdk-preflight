package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-entity-type-reserved-word", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("entity type %v in namespace %v is a Cedar reserved word; CreatePolicyStore answers \"this identifier is reserved and cannot be used: %v\"", [t, nsname, t]),
	"Rename the entity type; true, false, if, then, else, in, is, like and has are Cedar keywords",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, nsname, t, _] in _pf_avpsch_ets
	t in {"true", "false", "if", "then", "else", "in", "is", "like", "has"}
}
