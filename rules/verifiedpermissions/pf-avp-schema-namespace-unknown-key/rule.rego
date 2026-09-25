package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-namespace-unknown-key", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("namespace %v declares %v, which is not a Cedar schema key; CreatePolicyStore answers \"unknown field `%v`, expected one of `commonTypes`, `entityTypes`, `actions`, `annotations`\"", [nsname, k, k]),
	"Remove the key, or move it under entityTypes / actions / commonTypes / annotations",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, nsname, def] in _pf_avpsch_ns
	some k, _ in def
	not k in {"commonTypes", "entityTypes", "actions", "annotations"}
}
