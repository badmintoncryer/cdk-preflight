package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-scope-is-with-equals", "ERROR", name, path,
	sprintf("scope element (%v) combines is with ==; only 'is T in E' is allowed", [trim_space(p)]),
	"Drop the is clause, or combine it with in instead of ==",
	"https://docs.cedarpolicy.com/policies/syntax-grammar.html") if {
	some [name, path, s] in _pf_cedarlib_all
	some p in _pf_cedarlib_parts(s)
	_pf_cedarlib_word(p) in {"principal", "resource"}
	_pf_cedarlib_is_op(p) == true
	contains(p, "==")
}
