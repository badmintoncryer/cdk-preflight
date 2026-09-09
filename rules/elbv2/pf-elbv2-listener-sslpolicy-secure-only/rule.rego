package cdk_preflight

import rego.v1

_pf_elblss_fix := "Drop SslPolicy, or make the listener HTTPS (ALB) or TLS (NLB)"

_pf_elblss_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html"

violation contains make_diag_full("pf-elbv2-listener-sslpolicy-secure-only", "ERROR", name,
	"Properties.SslPolicy",
	sprintf("SslPolicy is set on a %s listener; a security policy only applies where the listener terminates TLS", [proto]),
	_pf_elblss_fix, _pf_elblss_url) if {
	some name in _pf_elb_listeners
	_pf_elb_has(name, "SslPolicy")
	proto := object.get(_pf_elb_props(name), "Protocol", "GENEVE")
	not proto in _pf_elb_secure
}
