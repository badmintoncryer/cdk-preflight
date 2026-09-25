package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-entity-id-quoted", "ERROR", name, path,
	sprintf("entity reference %v in the scope has an unquoted identifier; a UID is Namespace::Type::\"id\"", [tok]),
	"Quote the identifier, e.g. MyApp::User::\"alice\"",
	"https://docs.cedarpolicy.com/policies/syntax-grammar.html") if {
	some [name, path, s] in _pf_cedarlib_all
	sc := _pf_cedarlib_scope(s)
	_pf_cedarlib_is_op(sc) == false
	some tok in _pf_cedarlib_paths(sc)
	contains(tok, "::")
	not endswith(tok, `::""`)
}
