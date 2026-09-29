package cdk_preflight

import rego.v1

_pf_eb_opt_elb_listener_layer_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

_pf_eb_opt_elb_listener_layer_layer := {"HTTP": 7, "HTTPS": 7, "TCP": 4, "SSL": 4}

violation contains make_diag_full("pf-elasticbeanstalk-opt-elb-listener-layer", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Listener %s has ListenerProtocol %s and InstanceProtocol %s; an HTTP/HTTPS listener can only forward to HTTP/HTTPS and a TCP/SSL listener only to TCP/SSL", [o.ns, lp, o.s]),
	"Use an InstanceProtocol on the same layer as ListenerProtocol (HTTP or HTTPS with HTTP or HTTPS, TCP or SSL with TCP or SSL)", _pf_eb_opt_elb_listener_layer_url) if {
	o := _pf_eblib_opt[_]
	o.k == "aws:elb:listener|InstanceProtocol"
	_pf_eblib_clean(o.rn)
	_pf_eblib_lbtype(o.rn) == "classic"
	count(_pf_eblib_nsvals(o.rn, o.ns, "InstanceProtocol")) == 1
	vs := _pf_eblib_nsvals(o.rn, o.ns, "ListenerProtocol")
	count(vs) == 1
	lp := vs[0]
	_pf_eb_opt_elb_listener_layer_layer[lp] != _pf_eb_opt_elb_listener_layer_layer[o.s]
}
