package cdk_preflight

import rego.v1

_pf_ledfc_fix := "Drop FilterCriteria and filter inside the function"

_pf_ledfc_url := "https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html"

violation contains make_diag_full("pf-lambda-esm-filter-criteria-docdb-unsupported", "ERROR", name,
	"Properties.FilterCriteria",
	"FilterCriteria on a DocumentDB event source; Lambda applies no event filtering to DocumentDB change streams and the mapping create is rejected",
	_pf_ledfc_fix, _pf_ledfc_url) if {
	some name in _pf_lam_esm
	_pf_lam_is(name, "docdb")
	_pf_lam_has(name, "FilterCriteria")
}
