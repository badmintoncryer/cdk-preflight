package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-column-duplicate-name", "ERROR", name, concat(".", [p2, "ColumnName"]),
	sprintf("column %v is declared more than once across PartitionKeyColumns / ClusteringKeyColumns / RegularColumns; Keyspaces answers \"duplicate AllColumns can not be declared\"", [n]),
	"Give every column a distinct name",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/cql.ddl.table.html") if {
	some [name, k1, p1, c1] in _pf_cass_rawcol
	k1 != "field"
	n := object.get(c1, "ColumnName", null)
	is_string(n)
	some x in _pf_cass_rawcol
	x[0] == name
	x[1] != "field"
	p2 := x[2]
	c2 := x[3]
	p1 < p2
	object.get(c2, "ColumnName", null) == n
}
