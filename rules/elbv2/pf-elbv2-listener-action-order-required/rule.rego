package cdk_preflight

import rego.v1

_pf_elblaor_fix := "Give every action an Order (authentication first, routing last)"

_pf_elblaor_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html"

violation contains make_diag_full("pf-elbv2-listener-action-order-required", "ERROR", name,
	sprintf("Properties.DefaultActions.%d.Order", [a.index]),
	"DefaultActions holds more than one action but this one has no Order; the service needs the order to know which action runs first",
	_pf_elblaor_fix, _pf_elblaor_url) if {
	some name in _pf_elb_listeners
	acts := _pf_elb_actions(name, "DefaultActions")
	count(acts) > 1
	some a in acts
	not _pf_elb_ohas(a.value, "Order")
}
