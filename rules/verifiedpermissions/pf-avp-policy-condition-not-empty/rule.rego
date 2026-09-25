package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-condition-not-empty", "ERROR", name, path,
	sprintf("an empty when/unless clause: %v", [trim_space(c)]),
	"Put an expression in the clause, or drop the clause",
	"https://docs.cedarpolicy.com/policies/syntax-grammar.html") if {
	some [name, path, s] in _pf_cedarlib_all
	c := _pf_cedarlib_code(s)
	regex.match(`(^|[^A-Za-z_0-9])(when|unless)[ \t\r\n]*\{[ \t\r\n]*\}`, c)
}
