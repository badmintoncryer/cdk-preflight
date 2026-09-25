package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-avp-policy-reserved-identifier", "ERROR", name, path,
	sprintf("entity reference %v uses the reserved word %v as a name segment", [tok, seg]),
	"Rename the namespace or entity type so it is not a Cedar reserved word",
	"https://docs.cedarpolicy.com/policies/syntax-grammar.html") if {
	some [name, path, s] in _pf_cedarlib_all
	some tok in _pf_cedarlib_paths(_pf_cedarlib_scope(s))
	contains(tok, "::")
	some seg in split(tok, "::")
	seg in {"true", "false", "if", "then", "else", "in", "like", "has", "is", "__cedar"}
}
