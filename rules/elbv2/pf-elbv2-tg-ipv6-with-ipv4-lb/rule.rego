package cdk_preflight

import rego.v1

_pf_elbtgil_fix := "Give the load balancer IpAddressType: dualstack, or make the target group ipv4"

_pf_elbtgil_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-listeners.html"

violation contains make_diag_full("pf-elbv2-tg-ipv6-with-ipv4-lb", "ERROR", p.tg,
	"Properties.IpAddressType",
	sprintf("The target group is IPv6 but listener '%s' hangs off a load balancer with an 'ipv4' IP address type", [p.listener]),
	_pf_elbtgil_fix, _pf_elbtgil_url) if {
	some p in _pf_elb_listener_tgs
	object.get(_pf_elb_props(p.tg), "IpAddressType", "ipv4") == "ipv6"
	lb := _pf_elb_lb_of(p.listener)
	object.get(_pf_elb_props(lb), "IpAddressType", "ipv4") == "ipv4"
}
