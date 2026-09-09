package cdk_preflight

import rego.v1

_pf_elbldal_fix := "End DefaultActions with a forward, redirect or fixed-response action"

_pf_elbldal_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html"

_pf_elbldal_last(acts) := t if {
	orders := [o | some a in acts; o := object.get(a.value, "Order", null); is_number(o)]
	count(orders) == count(acts)
	some a in acts
	object.get(a.value, "Order", null) == max(orders)
	t := object.get(a.value, "Type", "")
}

_pf_elbldal_last(acts) := t if {
	orders := [o | some a in acts; o := object.get(a.value, "Order", null); is_number(o)]
	count(orders) != count(acts)
	some a in acts
	a.index == max([x.index | some x in acts])
	t := object.get(a.value, "Type", "")
}

violation contains make_diag_full("pf-elbv2-listener-default-action-routing-last", "ERROR", name,
	"Properties.DefaultActions",
	sprintf("The last default action is '%s'; an action list has to end on a forward, redirect or fixed-response action", [t]),
	_pf_elbldal_fix, _pf_elbldal_url) if {
	some name in _pf_elb_listeners
	acts := _pf_elb_actions(name, "DefaultActions")
	count(acts) > 0
	t := _pf_elbldal_last(acts)
	not t in _pf_elb_routing_actions
}
