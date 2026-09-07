package cdk_preflight

import rego.v1

_pf_lefla_fix := "Wrap the match value in an array, e.g. {\"id\": [\"a\"]}"

_pf_lefla_url := "https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html"

violation contains make_diag_full("pf-lambda-esm-filter-pattern-leaf-array", "ERROR", name,
	sprintf("Properties.FilterCriteria.Filters[%v].Pattern", [i]),
	sprintf("the pattern matches '%v' against a bare value; EventBridge syntax requires every leaf to be an array of match values", [concat(".", entry[0])]),
	_pf_lefla_fix, _pf_lefla_url) if {
	some name in _pf_lam_esm
	some i, f in _pf_lam_filters(name)
	some entry in _pf_lam_pat_scalars(_pf_lam_pat(f))
}
