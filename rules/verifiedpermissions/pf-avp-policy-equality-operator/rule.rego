package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-equality-operator", "ERROR", name, path,
	sprintf("policy scope (%v) uses a single '='; the scope operators are ==, in and is", [sc]),
	"Use == for equality in the scope",
	"https://docs.cedarpolicy.com/policies/syntax-grammar.html") if {
	some [name, path, s] in _pf_cedarlib_all
	sc := _pf_cedarlib_scope(s)
	regex.match(`[^=]=[^=]`, concat("", [" ", sc, " "]))
}
