package cdk_preflight

import rego.v1

_pf_elbpip_fix := "Set Scheme to internal on a network load balancer, or drop PrivateIPv4Address"

_pf_elbpip_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html"

_pf_elbpip_internal_nlb(name) if {
	_pf_elb_lbtype(name) == "network"
	object.get(_pf_elb_props(name), "Scheme", "internet-facing") == "internal"
}

violation contains make_diag_full("pf-elbv2-lb-private-ipv4-internal-only", "ERROR", name,
	sprintf("Properties.SubnetMappings.%d.PrivateIPv4Address", [m.index]),
	"PrivateIPv4Address is mapped on a load balancer that is not an internal network load balancer; CreateLoadBalancer fails with \"You can only specify private IPv4 addresses for Network Load Balancers with scheme 'internal'.\"",
	_pf_elbpip_fix, _pf_elbpip_url) if {
	some name in _pf_elb_lbs
	not _pf_elbpip_internal_nlb(name)
	some m in flatten_list(name, "Properties.SubnetMappings")
	_pf_elb_ohas(m.value, "PrivateIPv4Address")
}
