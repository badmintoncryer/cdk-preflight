package cdk_preflight

import rego.v1

_pf_lektr_fix := "List exactly one topic in Topics"

_pf_lektr_url := "https://docs.aws.amazon.com/lambda/latest/dg/msk-esm-parameters.html"

violation contains make_diag_full("pf-lambda-esm-msk-topics-required", "ERROR", name,
	"Properties.Topics",
	"a Kafka event source without Topics; Lambda has no topic to subscribe the poller to and the mapping create is rejected",
	_pf_lektr_fix, _pf_lektr_url) if {
	some name in _pf_lam_esm
	_pf_lam_is(name, "kafka")
	not _pf_lam_has(name, "Topics")
}
