package cdk_preflight

import rego.v1

_pf_elbdwp_fix := "Use dualstack on a network load balancer, or make this an application load balancer"

_pf_elbdwp_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html"

violation contains make_diag_full("pf-elbv2-lb-dualstack-no-public-ipv4-alb-only", "ERROR", name,
	"Properties.IpAddressType",
	sprintf("IpAddressType 'dualstack-without-public-ipv4' is set on a %s load balancer; CreateLoadBalancer fails with \"The specified IP address type is not supported on load balancers with type '%s'.\"", [t, t]),
	_pf_elbdwp_fix, _pf_elbdwp_url) if {
	some name in _pf_elb_lbs
	t := _pf_elb_lbtype(name)
	t != "application"
	_pf_elb_str(name, "IpAddressType") == "dualstack-without-public-ipv4"
}
