package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-frozen-on-scalar", "ERROR", name, path,
	sprintf("%v %v puts frozen<> around the scalar type %v; Keyspaces answers \"frozen<> is only allowed on collections, tuples, and user-defined types\"", [path, t, c.n]),
	"Drop frozen<> around scalar types",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/cql.elements.html") if {
	some [name, _, path, t] in _pf_cass_col
	nodes := _pf_cass_nodes(t)
	some n in nodes
	n.n == "frozen"
	n.open
	some c in nodes
	c.p == n.i
	not c.open
	c.n in _pf_cass_scalars
}
