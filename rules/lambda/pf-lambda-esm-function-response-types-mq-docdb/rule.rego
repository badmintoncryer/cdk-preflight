package cdk_preflight

import rego.v1

_pf_lemfr_fix := "Drop FunctionResponseTypes for Amazon MQ and DocumentDB sources"

_pf_lemfr_url := "https://docs.aws.amazon.com/lambda/latest/dg/services-mq-params.html"

violation contains make_diag_full("pf-lambda-esm-function-response-types-mq-docdb", "ERROR", name,
	"Properties.FunctionResponseTypes",
	"FunctionResponseTypes on an Amazon MQ or DocumentDB event source; neither reports partial batch failures, so the mapping create is rejected",
	_pf_lemfr_fix, _pf_lemfr_url) if {
	some name in _pf_lam_esm
	_pf_lam_has(name, "FunctionResponseTypes")
	some kind in {"mq", "docdb"}
	_pf_lam_is(name, kind)
}
