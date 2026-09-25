package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-scope-order", "ERROR", name, path,
	sprintf("policy scope is ordered %v; Cedar requires principal, action, resource", [words]),
	"Reorder the scope to principal, action, resource",
	"https://docs.cedarpolicy.com/policies/syntax-grammar.html") if {
	some [name, path, s] in _pf_cedarlib_all
	parts := _pf_cedarlib_parts(s)
	count(parts) == 3
	words := [w | some p in parts; w := _pf_cedarlib_word(p)]
	count(words) == 3
	words != ["principal", "action", "resource"]
}
