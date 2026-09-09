package cdk_preflight

import rego.v1

_pf_elblat_fix := "Drop AlpnPolicy unless the listener protocol is TLS"

_pf_elblat_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html"

violation contains make_diag_full("pf-elbv2-listener-alpn-tls-only", "ERROR", name,
	"Properties.AlpnPolicy",
	sprintf("AlpnPolicy is set on a %s listener; CreateListener answers \"You cannot set ALPN policy on load balancers of type '%s'\"", [proto, t]),
	_pf_elblat_fix, _pf_elblat_url) if {
	some name in _pf_elb_listeners
	_pf_elb_has(name, "AlpnPolicy")
	proto := object.get(_pf_elb_props(name), "Protocol", "GENEVE")
	proto != "TLS"
	t := _pf_elb_listener_lbtype(name)
}
