package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-like-pattern-string", "ERROR", name, path,
	sprintf("like is applied to a non-string operand: %v", [trim_space(c)]),
	"Compare against a quoted pattern, e.g. principal.name like \"a*\"",
	"https://docs.cedarpolicy.com/policies/syntax-grammar.html") if {
	some [name, path, s] in _pf_cedarlib_all
	c := _pf_cedarlib_code(s)
	regex.match(`(^|[^A-Za-z_0-9])like([ \t\r\n]+[^"\s]|[^A-Za-z_0-9\s"])`, c)
}
