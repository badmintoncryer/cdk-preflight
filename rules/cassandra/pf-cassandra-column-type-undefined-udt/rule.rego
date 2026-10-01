package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-column-type-undefined-udt", "ERROR", name, path,
	sprintf("%v %v names %v, which is neither a built-in CQL type nor an AWS::Cassandra::Type in this keyspace; Keyspaces answers \"UDT %v does not exist\"", [path, t, n.n, n.n]),
	"Fix the type name (text, bigint, boolean, timestamp ...), or add the AWS::Cassandra::Type to the same keyspace",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/udts.html") if {
	some [name, _, path, t] in _pf_cass_col
	_pf_cass_ks(name)
	some n in _pf_cass_nodes(t)
	not n.open
	not n.n in _pf_cass_scalars
	not n.n in _pf_cass_keywords
	regex.match(`^[a-z][a-z0-9_]*$`, n.n)
	not _pf_cass_is_udt(name, n.n)
}
