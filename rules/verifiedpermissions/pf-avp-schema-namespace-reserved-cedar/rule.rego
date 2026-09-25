package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-namespace-reserved-cedar", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("namespace %v uses the reserved segment __cedar; CreatePolicyStore answers \"The name `%v` contains `__cedar`, which is reserved\"", [nsname, nsname]),
	"Rename the namespace; __cedar is reserved for Cedar's own declarations",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, nsname, _] in _pf_avpsch_ns
	some seg in split(nsname, "::")
	seg == "__cedar"
}
