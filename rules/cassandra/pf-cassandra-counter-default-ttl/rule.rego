package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-cassandra-counter-default-ttl", "ERROR", name, "Properties.DefaultTimeToLive",
	sprintf("DefaultTimeToLive is %v on a table with counter columns; Keyspaces answers \"Cannot set default_time_to_live on a table with counters\"", [ttl]),
	"Set DefaultTimeToLive to 0 (or omit it) on counter tables",
	"https://docs.aws.amazon.com/keyspaces/latest/devguide/cql.elements.html#cql.data-types.numeric.counters") if {
	some [name, "reg", _, c] in _pf_cass_col
	lower(trim_space(c)) == "counter"
	ttl := to_number(resolve(name, "Properties.DefaultTimeToLive"))
	ttl > 0
}
