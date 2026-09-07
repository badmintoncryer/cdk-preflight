package cdk_preflight

import rego.v1

_pf_lemas_fix := "Add a SourceAccessConfigurations entry of type BASIC_AUTH pointing at a Secrets Manager secret"

_pf_lemas_url := "https://docs.aws.amazon.com/lambda/latest/dg/with-mq.html"

_pf_lemas_basic(name) if {
	some c in _pf_lam_list(_pf_lam_get(name, "SourceAccessConfigurations"))
	is_object(c)
	object.get(c, "Type", "") == "BASIC_AUTH"
}

violation contains make_diag_full("pf-lambda-esm-mq-auth-secret-required", "ERROR", name,
	"Properties.SourceAccessConfigurations",
	"an Amazon MQ event source without BASIC_AUTH credentials; Lambda signs into the broker with a Secrets Manager secret and the mapping create is rejected without one",
	_pf_lemas_fix, _pf_lemas_url) if {
	some name in _pf_lam_esm
	_pf_lam_is(name, "mq")
	not _pf_lemas_basic(name)
}
