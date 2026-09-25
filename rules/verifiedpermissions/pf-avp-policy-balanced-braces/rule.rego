package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-balanced-braces", "ERROR", name, path,
	sprintf("statement has %v %v against %v %v", [opens - 1, pair[0], closes - 1, pair[1]]),
	"Close every brace and parenthesis the statement opens",
	"https://docs.cedarpolicy.com/policies/syntax-grammar.html") if {
	some [name, path, s] in _pf_cedarlib_all
	c := _pf_cedarlib_code(s)
	some pair in [["{", "}"], ["(", ")"]]
	opens := count(split(c, pair[0]))
	closes := count(split(c, pair[1]))
	opens != closes
}
