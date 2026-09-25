package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-namespace-identifier", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("namespace %v is not a Cedar path (Ident(::Ident)*); CreatePolicyStore answers \"invalid namespace `%v`\"", [nsname, nsname]),
	"Spell the namespace with letters, digits and underscores only, e.g. MyApp or My::App",
	"https://docs.cedarpolicy.com/schema/json-schema.html") if {
	some [name, nsname, _] in _pf_avpsch_ns
	count(nsname) > 0
	not regex.match(`^[A-Za-z_][A-Za-z_0-9]*(?:::[A-Za-z_][A-Za-z_0-9]*)*$`, nsname)
}
