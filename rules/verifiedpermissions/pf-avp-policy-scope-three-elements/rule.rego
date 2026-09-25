package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-scope-three-elements", "ERROR", name, path,
	sprintf("policy scope has %v elements; it must be exactly principal, action, resource", [count(parts)]),
	"Write all three scope elements, e.g. permit(principal, action, resource)",
	"https://docs.cedarpolicy.com/policies/syntax-grammar.html") if {
	some [name, path, s] in _pf_cedarlib_all
	parts := _pf_cedarlib_parts(s)
	count(parts) != 3
}
