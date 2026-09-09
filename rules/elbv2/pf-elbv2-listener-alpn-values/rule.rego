package cdk_preflight

import rego.v1

_pf_elblav_fix := "Use HTTP1Only, HTTP2Only, HTTP2Optional, HTTP2Preferred or None"

_pf_elblav_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html"

violation contains make_diag_full("pf-elbv2-listener-alpn-values", "ERROR", name,
	sprintf("Properties.AlpnPolicy.%d", [a.index]),
	sprintf("'%s' is not an ALPN policy; the accepted values are HTTP1Only, HTTP2Only, HTTP2Optional, HTTP2Preferred and None", [a.value]),
	_pf_elblav_fix, _pf_elblav_url) if {
	some name in _pf_elb_listeners
	some a in flatten_list(name, "Properties.AlpnPolicy")
	_pf_elb_lit(a.value)
	not a.value in {"HTTP1Only", "HTTP2Only", "HTTP2Optional", "HTTP2Preferred", "None"}
}
