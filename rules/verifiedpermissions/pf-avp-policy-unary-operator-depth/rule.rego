package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-unary-operator-depth", "ERROR", name, path,
	sprintf("%v chains %v unary operators; the grammar allows at most 4", [run, count(run)]),
	"Reduce the run of ! or - to four or fewer",
	"https://docs.cedarpolicy.com/policies/syntax-grammar.html") if {
	some [name, path, s] in _pf_cedarlib_all
	some run in regex.find_n(`[!\-]+`, _pf_cedarlib_code(s), -1)
	count(run) > 4
}
