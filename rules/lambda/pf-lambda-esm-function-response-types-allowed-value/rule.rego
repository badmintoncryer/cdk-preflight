package cdk_preflight

import rego.v1

_pf_lefrt_fix := "Use exactly \"ReportBatchItemFailures\""

_pf_lefrt_url := "https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html"

violation contains make_diag_full("pf-lambda-esm-function-response-types-allowed-value", "ERROR", name,
	"Properties.FunctionResponseTypes",
	sprintf("FunctionResponseTypes lists '%v'; the only accepted value is ReportBatchItemFailures", [v]),
	_pf_lefrt_fix, _pf_lefrt_url) if {
	some name in _pf_lam_esm
	l := _pf_lam_get(name, "FunctionResponseTypes")
	is_array(l)
	some v in l
	is_string(v)
	v != "ReportBatchItemFailures"
}
