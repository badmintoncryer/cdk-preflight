package cdk_preflight

import rego.v1

_pf_elbludp_fix := "Keep the load balancer on IpAddressType ipv4, or use a TCP/TLS listener"

_pf_elbludp_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html"

violation contains make_diag_full("pf-elbv2-listener-udp-dualstack", "ERROR", name,
	"Properties.Protocol",
	sprintf("A %s listener sits on a dualstack load balancer; UDP-based listeners are only available on an IPv4 network load balancer", [proto]),
	_pf_elbludp_fix, _pf_elbludp_url) if {
	some name in _pf_elb_listeners
	proto := _pf_elb_str(name, "Protocol")
	proto in {"UDP", "TCP_UDP", "QUIC", "TCP_QUIC"}
	lb := _pf_elb_lb_of(name)
	object.get(_pf_elb_props(lb), "IpAddressType", "ipv4") == "dualstack"
}
