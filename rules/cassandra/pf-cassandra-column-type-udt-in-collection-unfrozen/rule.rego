package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-column-type-udt-in-collection-unfrozen", "ERROR", name, path,
	sprintf("%v %v puts the user-defined type %v inside a collection without frozen<>; Keyspaces answers \"Non-frozen UDTs are not allowed inside collections\"", [path, t, n.n]),
	"Wrap the UDT in frozen<...>, e.g. list<frozen<address>>",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/keyspaces-create-udt.html") if {
	some [name, _, path, t] in _pf_cass_col
	nodes := _pf_cass_nodes(t)
	not "frozen" in {x.n | some x in nodes}
	some n in nodes
	not n.open
	_pf_cass_is_udt(name, n.n)
	n.p >= 0
	_pf_cass_node_name(nodes, n.p) in _pf_cass_collections
}
