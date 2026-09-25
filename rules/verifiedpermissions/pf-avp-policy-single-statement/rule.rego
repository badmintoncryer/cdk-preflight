package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-single-statement", "ERROR", name, path,
	sprintf("the property holds %v Cedar statements; Verified Permissions takes exactly one", [n]),
	"Split the statements into one Policy (or PolicyTemplate) resource each",
	"https://docs.cedarpolicy.com/policies/syntax-grammar.html") if {
	some [name, path, s] in _pf_cedarlib_all
	n := _pf_cedarlib_semicolons(s)
	n > 1
}
