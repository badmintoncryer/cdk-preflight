package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-type-nested-udt-unfrozen", "ERROR", name, path,
	sprintf("%v %v is a non-frozen user-defined type; Keyspaces answers \"A user type cannot contain non-frozen UDTs\"", [path, t]),
	"Declare the field as frozen<...>, e.g. frozen<address>",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/cql.ddl.type.html") if {
	some [name, "field", path, t] in _pf_cass_col
	some n in _pf_cass_nodes(t)
	n.d == 0
	not n.open
	_pf_cass_is_udt(name, n.n)
}
