package cdk_preflight

import rego.v1

_pf_elblatp_fix := "Forward to the TargetType: alb target group from a TCP listener of a Network Load Balancer"

_pf_elblatp_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-listeners.html"

violation contains make_diag_full("pf-elbv2-listener-alb-target-tg-listener-protocol", "ERROR", p.listener,
	"Properties.Protocol",
	sprintf("Target group '%s' targets an Application Load Balancer but the listener is %s; only a TCP listener of a Network Load Balancer can forward to it", [p.tg, proto]),
	_pf_elblatp_fix, _pf_elblatp_url) if {
	some p in _pf_elb_listener_tgs
	_pf_elb_tgtype(p.tg) == "alb"
	proto := object.get(_pf_elb_props(p.listener), "Protocol", "")
	proto != "TCP"
}
