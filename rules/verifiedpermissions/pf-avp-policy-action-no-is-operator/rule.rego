package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-action-no-is-operator", "ERROR", name, path,
	sprintf("action element (%v) uses is; the grammar allows is only on principal and resource", [trim_space(p)]),
	"Constrain the action with == or in, e.g. action == MyApp::Action::\"view\"",
	"https://docs.cedarpolicy.com/policies/syntax-grammar.html") if {
	some [name, path, s] in _pf_cedarlib_all
	some p in _pf_cedarlib_parts(s)
	_pf_cedarlib_word(p) == "action"
	_pf_cedarlib_is_op(p) == true
}
