package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-extension-name-known", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("%v in namespace %v is the extension %v; CreatePolicyStore answers \"unknown extension type `%v`\"", [p, nsname, n, n]),
	"Use one of Cedar's extension types: ipaddr, decimal, datetime or duration",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, nsname, p, t] in _pf_avpsch_types
	object.get(t, "type", null) == "Extension"
	n := object.get(t, "name", null)
	is_string(n)
	not n in {"ipaddr", "decimal", "datetime", "duration"}
}
