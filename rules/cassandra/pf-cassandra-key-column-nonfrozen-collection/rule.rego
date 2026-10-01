package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-key-column-nonfrozen-collection", "ERROR", name, path,
	sprintf("%v %v is a non-frozen collection or user-defined type in the primary key; Keyspaces answers \"Invalid non-frozen collection type for PRIMARY KEY component\"", [path, t]),
	"Declare the key column as frozen<...>, or move it out of the primary key",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/cql.elements.html") if {
	some [name, kind, path, t] in _pf_cass_col
	kind in {"pk", "ck"}
	some n in _pf_cass_nodes(t)
	n.d == 0
	_pf_casskey_unfrozen(name, n)
}

_pf_casskey_unfrozen(_, n) if {
	n.open
	n.n in _pf_cass_collections
}

_pf_casskey_unfrozen(name, n) if {
	not n.open
	_pf_cass_is_udt(name, n.n)
}
