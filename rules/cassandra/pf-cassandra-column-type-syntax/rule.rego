package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-column-type-syntax", "ERROR", name, path,
	sprintf("%v %v is not a valid CQL type: unbalanced <> or a wrong number of type arguments (map takes 2, list / set / frozen take 1, tuple at least 1)", [path, t]),
	"Write the type as map<K, V>, list<T>, set<T>, frozen<T> or tuple<T, ...> with matching angle brackets",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/cql.elements.html#cql.data-types.collection") if {
	some [name, _, path, t] in _pf_cass_col
	_pf_cassyn_bad(t)
}

_pf_cassyn_arity := {"list": 1, "set": 1, "map": 2, "frozen": 1}

_pf_cassyn_bad(t) if {
	toks := _pf_cass_toks(t)
	_pf_cass_depth(toks, count(toks)) != 0
}

_pf_cassyn_bad(t) if {
	toks := _pf_cass_toks(t)
	some i, _ in toks
	_pf_cass_depth(toks, i + 1) < 0
}

_pf_cassyn_bad(t) if {
	nodes := _pf_cass_nodes(t)
	some n in nodes
	n.open
	want := _pf_cassyn_arity[n.n]
	count([1 | some c in nodes; c.p == n.i]) != want
}

_pf_cassyn_bad(t) if {
	nodes := _pf_cass_nodes(t)
	some n in nodes
	n.open
	n.n == "tuple"
	count([1 | some c in nodes; c.p == n.i]) == 0
}
