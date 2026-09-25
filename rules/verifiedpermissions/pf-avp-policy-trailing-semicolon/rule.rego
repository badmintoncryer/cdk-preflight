package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-trailing-semicolon", "ERROR", name, path,
	sprintf("Cedar statement does not end with ';': %v", [t]),
	"Terminate the statement with a semicolon",
	"https://docs.cedarpolicy.com/policies/syntax-grammar.html") if {
	some [name, path, s] in _pf_cedarlib_all
	t := trim_space(_pf_cedarlib_code(s))
	count(t) > 0
	not endswith(t, ";")
}
