package cdk_preflight

import rego.v1

_pf_lemra_fix := "Drop MaximumRecordAgeInSeconds, or point the mapping at a stream source"

_pf_lemra_url := "https://docs.aws.amazon.com/lambda/latest/api/API_CreateEventSourceMapping.html"

violation contains make_diag_full("pf-lambda-esm-maximum-record-age-stream-only", "ERROR", name,
	"Properties.MaximumRecordAgeInSeconds",
	"MaximumRecordAgeInSeconds on a source that does not support it; record age is a stream retention concept and queues do not carry it",
	_pf_lemra_fix, _pf_lemra_url) if {
	some name in _pf_lam_esm
	_pf_lam_has(name, "MaximumRecordAgeInSeconds")
	some other in ["sqs","mq","docdb"]
	_pf_lam_is(name, other)
}
