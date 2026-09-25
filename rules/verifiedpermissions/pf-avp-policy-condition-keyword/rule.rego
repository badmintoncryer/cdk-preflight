package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-condition-keyword", "ERROR", name, path,
	sprintf("condition clause starts with %v; Cedar has only when and unless", [ws[0]]),
	"Rename the clause to when { ... } or unless { ... }",
	"https://docs.cedarpolicy.com/policies/syntax-grammar.html") if {
	some [name, path, s] in _pf_cedarlib_all
	_pf_cedarlib_semicolons(s) <= 1
	ws := regex.find_n(`^[A-Za-z_][A-Za-z_0-9]*`, trim_space(_pf_cedarlib_body(s)), 1)
	count(ws) == 1
	not ws[0] in {"when", "unless"}
}
