package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-comment-syntax", "ERROR", name, path,
	sprintf("statement carries a '#' outside a string literal; Cedar comments start with // (%v)", [trim_space(c)]),
	"Start the comment with // instead of #",
	"https://docs.cedarpolicy.com/policies/syntax-grammar.html") if {
	some [name, path, s] in _pf_cedarlib_all
	c := _pf_cedarlib_code(s)
	contains(c, "#")
}
