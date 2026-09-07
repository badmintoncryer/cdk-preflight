package cdk_preflight

import rego.v1

_pf_lemrs_fix := "Drop MaximumRetryAttempts, or point the mapping at a stream source"

_pf_lemrs_url := "https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html"

violation contains make_diag_full("pf-lambda-esm-maximum-retry-attempts-stream-only", "ERROR", name,
	"Properties.MaximumRetryAttempts",
	"MaximumRetryAttempts on a source that does not support it; queue sources retry through the queue redrive policy instead",
	_pf_lemrs_fix, _pf_lemrs_url) if {
	some name in _pf_lam_esm
	_pf_lam_has(name, "MaximumRetryAttempts")
	some other in ["sqs","mq","docdb"]
	_pf_lam_is(name, other)
}
