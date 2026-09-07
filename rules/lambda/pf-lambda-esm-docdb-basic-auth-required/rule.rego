package cdk_preflight

import rego.v1

_pf_ledba_fix := "Add a SourceAccessConfigurations entry of type BASIC_AUTH pointing at a Secrets Manager secret"

_pf_ledba_url := "https://docs.aws.amazon.com/lambda/latest/dg/with-documentdb.html"

_pf_ledba_basic(name) if {
	some c in _pf_lam_list(_pf_lam_get(name, "SourceAccessConfigurations"))
	is_object(c)
	object.get(c, "Type", "") == "BASIC_AUTH"
}

violation contains make_diag_full("pf-lambda-esm-docdb-basic-auth-required", "ERROR", name,
	"Properties.SourceAccessConfigurations",
	"a DocumentDB event source without BASIC_AUTH credentials; Lambda opens the change stream with a Secrets Manager secret and the mapping create is rejected without one",
	_pf_ledba_fix, _pf_ledba_url) if {
	some name in _pf_lam_esm
	_pf_lam_is(name, "docdb")
	not _pf_ledba_basic(name)
}
