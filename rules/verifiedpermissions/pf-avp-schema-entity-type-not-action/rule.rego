package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-entity-type-not-action", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("namespace %v declares the entity type Action; CreatePolicyStore answers \"entity type `Action` declared in `entityTypes` list\"", [nsname]),
	"Declare actions under the actions key; Cedar reserves the Action entity type for them",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, nsname, t, _] in _pf_avpsch_ets
	t == "Action"
}
