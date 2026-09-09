package cdk_preflight

import rego.v1

_pf_elbltpm_fix := "Line the target group protocol up with the listener protocol"

_pf_elbltpm_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-listeners.html"

violation contains make_diag_full("pf-elbv2-listener-tg-protocol-match", "ERROR", p.listener,
	"Properties.Protocol",
	sprintf("The listener is %s but target group '%s' is %s; the listener and the target group have incompatible protocols", [lproto, p.tg, tproto]),
	_pf_elbltpm_fix, _pf_elbltpm_url) if {
	some p in _pf_elb_listener_tgs
	_pf_elb_tgtype(p.tg) != "alb"
	lproto := object.get(_pf_elb_props(p.listener), "Protocol", "")
	allowed := object.get(_pf_elb_lproto_tgproto, lproto, set())
	count(allowed) > 0
	tproto := _pf_elb_oget(_pf_elb_props(p.tg), "Protocol")
	not tproto in allowed
}
