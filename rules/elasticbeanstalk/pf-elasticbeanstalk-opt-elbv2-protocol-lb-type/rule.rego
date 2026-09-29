package cdk_preflight

import rego.v1

_pf_eb_opt_elbv2_protocol_lb_type_url := "https://docs.aws.amazon.com/elasticbeanstalk/latest/dg/command-options-general.html"

violation contains make_diag_full("pf-elasticbeanstalk-opt-elbv2-protocol-lb-type", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Listener %s has Protocol %s on a Network Load Balancer; a Network Load Balancer listener takes TCP or TLS", [o.ns, o.s]),
	"Use TCP or TLS on a Network Load Balancer listener, or set LoadBalancerType to application", _pf_eb_opt_elbv2_protocol_lb_type_url) if {
	o := _pf_eblib_opt[_]
	o.nm == "Protocol"
	o.s in {"HTTP", "HTTPS"}
	_pf_eblib_clean(o.rn)
	_pf_eblib_lbtype(o.rn) == "network"
	regex.match(`^aws:elbv2:listener:[^:]+$`, o.ns)
	count(_pf_eblib_nsvals(o.rn, o.ns, "Protocol")) == 1
}

violation contains make_diag_full("pf-elasticbeanstalk-opt-elbv2-protocol-lb-type", "ERROR", o.rn,
	sprintf("Properties.OptionSettings.%d.Value", [o.i]),
	sprintf("Process %s has Protocol %s on a Network Load Balancer; a Network Load Balancer only forwards to TCP processes", [o.ns, o.s]),
	"Use TCP for the process, or set LoadBalancerType to application", _pf_eb_opt_elbv2_protocol_lb_type_url) if {
	o := _pf_eblib_opt[_]
	o.nm == "Protocol"
	o.s in {"HTTP", "HTTPS"}
	_pf_eblib_clean(o.rn)
	_pf_eblib_lbtype(o.rn) == "network"
	regex.match(`^aws:elasticbeanstalk:environment:process:[^:]+$`, o.ns)
	count(_pf_eblib_nsvals(o.rn, o.ns, "Protocol")) == 1
}
