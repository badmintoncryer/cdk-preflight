package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-column-type-nonfrozen-nested-collection", "ERROR", name, path,
	sprintf("%v %v nests a non-frozen collection inside a collection; Keyspaces answers \"Non-frozen collections are not allowed inside collections\"", [path, t]),
	"Wrap the inner collection in frozen<...>, e.g. list<frozen<list<int>>>",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/cql.elements.html") if {
	some [name, _, path, t] in _pf_cass_col
	nodes := _pf_cass_nodes(t)
	not "frozen" in {n.n | some n in nodes}
	some n in nodes
	n.open
	n.n in _pf_cass_collections
	n.p >= 0
	_pf_cass_node_name(nodes, n.p) in _pf_cass_collections
}
