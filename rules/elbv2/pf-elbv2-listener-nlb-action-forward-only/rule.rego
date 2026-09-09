package cdk_preflight

import rego.v1

_pf_elblnaf_fix := "Use a forward action (redirect, fixed-response and authentication are Application Load Balancer features)"

_pf_elblnaf_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html"

violation contains make_diag_full("pf-elbv2-listener-nlb-action-forward-only", "ERROR", name,
	sprintf("Properties.DefaultActions.%d.Type", [a.index]),
	sprintf("A '%s' action is on a listener of a %s load balancer, which can only forward to a target group", [t, lbt]),
	_pf_elblnaf_fix, _pf_elblnaf_url) if {
	some name in _pf_elb_listeners
	lbt := _pf_elb_listener_lbtype(name)
	lbt != "application"
	some a in _pf_elb_actions(name, "DefaultActions")
	t := object.get(a.value, "Type", "")
	t != "forward"
}
