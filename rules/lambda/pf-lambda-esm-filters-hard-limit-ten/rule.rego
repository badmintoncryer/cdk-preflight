package cdk_preflight

import rego.v1

_pf_leflt_fix := "Keep at most 10 entries in FilterCriteria.Filters"

_pf_leflt_url := "https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html"

violation contains make_diag_full("pf-lambda-esm-filters-hard-limit-ten", "ERROR", name,
	"Properties.FilterCriteria.Filters",
	sprintf("%v filters on one event source mapping; 10 is a hard limit that a quota increase cannot raise", [n]),
	_pf_leflt_fix, _pf_leflt_url) if {
	some name in _pf_lam_esm
	n := count(_pf_lam_filters(name))
	n > 10
}
