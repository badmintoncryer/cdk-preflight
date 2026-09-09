package cdk_preflight

import rego.v1

_pf_elbv6a_fix := "Leave Scheme at internet-facing, or drop SubnetMappings[].IPv6Address"

_pf_elbv6a_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html"

violation contains make_diag_full("pf-elbv2-lb-ipv6-address-internet-facing-only", "ERROR", name,
	sprintf("Properties.SubnetMappings.%d.IPv6Address", [m.index]),
	"IPv6Address is mapped on an internal load balancer; a mapped IPv6 address is only accepted on an internet-facing dualstack network load balancer",
	_pf_elbv6a_fix, _pf_elbv6a_url) if {
	some name in _pf_elb_lbs
	object.get(_pf_elb_props(name), "Scheme", "internet-facing") != "internet-facing"
	some m in flatten_list(name, "Properties.SubnetMappings")
	_pf_elb_ohas(m.value, "IPv6Address")
}
