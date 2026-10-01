package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-counter-in-primary-key", "ERROR", name, path,
	sprintf("%v is counter in the primary key; Keyspaces answers \"counter type is not supported for PRIMARY KEY part\"", [path]),
	"Use a non-counter type for partition key and clustering columns",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/cql.elements.html#cql.data-types.numeric.counters") if {
	some [name, kind, path, t] in _pf_cass_col
	kind in {"pk", "ck"}
	lower(trim_space(t)) == "counter"
}
