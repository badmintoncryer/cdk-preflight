package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-schema-namespace-length", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("namespace name is %d bytes; CreatePolicyStore answers \"Namespace lengths must be at least 1 and at most 100 bytes in size, but '%v' is %d bytes in size\"", [count(nsname), nsname, count(nsname)]),
	"Name the namespace: Verified Permissions rejects the empty namespace that Cedar itself allows, and caps the name at 100 bytes",
	"https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/schema.html") if {
	some [name, nsname, _] in _pf_avpsch_ns
	count(nsname) == 0
}

violation contains make_diag_full("pf-avp-schema-namespace-length", "ERROR", name, "Properties.Schema.CedarJson",
	sprintf("namespace name is %d bytes; CreatePolicyStore answers \"Namespace lengths must be at least 1 and at most 100 bytes in size, but '%v' is %d bytes in size\"", [count(nsname), nsname, count(nsname)]),
	"Name the namespace: Verified Permissions rejects the empty namespace that Cedar itself allows, and caps the name at 100 bytes",
	"https://docs.aws.amazon.com/verifiedpermissions/latest/userguide/schema.html") if {
	some [name, nsname, _] in _pf_avpsch_ns
	count(nsname) > 100
}
