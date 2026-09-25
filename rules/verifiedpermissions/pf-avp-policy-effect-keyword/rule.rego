package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-effect-keyword", "ERROR", name, path,
	sprintf("Cedar statement starts with %v; the only effects are permit and forbid", [w]),
	"Start the statement with permit(...) or forbid(...)",
	"https://docs.cedarpolicy.com/policies/syntax-grammar.html") if {
	some [name, path, s] in _pf_cedarlib_all
	ws := regex.find_n(`[A-Za-z_][A-Za-z_0-9]*[ \t\r\n]*$`, _pf_cedarlib_head(s), 1)
	count(ws) == 1
	w := trim_space(ws[0])
	not w in {"permit", "forbid"}
}
