package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-counter-in-collection-or-udt", "ERROR", name, path,
	sprintf("%v %v uses counter inside a collection or a user-defined type; Keyspaces answers \"Counters are not allowed inside collections\" / \"A user type cannot contain counters\"", [path, t]),
	"Use bigint inside collections and UDT fields; counter only works as a plain table column",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/cql.elements.html") if {
	some [name, kind, path, t] in _pf_cass_col
	some n in _pf_cass_nodes(t)
	n.n == "counter"
	_pf_casscnt_nested(kind, n)
}

_pf_casscnt_nested(kind, _) if kind == "field"

_pf_casscnt_nested(kind, n) if {
	kind != "field"
	n.d > 0
}
