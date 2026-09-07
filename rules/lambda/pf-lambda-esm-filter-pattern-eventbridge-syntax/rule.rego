package cdk_preflight

import rego.v1

_pf_lefps_fix := "Write the Pattern as a JSON object, e.g. {\"body\": {\"id\": [\"a\"]}}"

_pf_lefps_url := "https://docs.aws.amazon.com/lambda/latest/dg/invocation-eventfiltering.html"

violation contains make_diag_full("pf-lambda-esm-filter-pattern-eventbridge-syntax", "ERROR", name,
	sprintf("Properties.FilterCriteria.Filters[%v].Pattern", [i]),
	"the filter Pattern is not a JSON object; Lambda parses it as an EventBridge event pattern and the mapping create is rejected",
	_pf_lefps_fix, _pf_lefps_url) if {
	some name in _pf_lam_esm
	some i, f in _pf_lam_filters(name)
	is_object(f)
	p := object.get(f, "Pattern", "__pf_absent")
	is_string(p)
	not _pf_lam_pat(f)
}
