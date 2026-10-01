package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-counter-mixed-columns", "ERROR", name, path,
	sprintf("%v is %v, but the table also has counter columns; Keyspaces answers \"Cannot mix counter and non counter columns in the same table\"", [path, t]),
	"Move the non-counter columns to a separate table, or make every regular column counter",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/cql.elements.html#cql.data-types.numeric.counters") if {
	some [name, "reg", _, c] in _pf_cass_col
	lower(trim_space(c)) == "counter"
	some x in _pf_cass_col
	x[0] == name
	x[1] == "reg"
	path := x[2]
	t := x[3]
	lower(trim_space(t)) != "counter"
}
