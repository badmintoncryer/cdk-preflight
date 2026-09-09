package cdk_preflight

import rego.v1

_pf_elbgs_fix := "Drop Scheme; a Gateway Load Balancer is always reached through its endpoint service"

_pf_elbgs_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html"

violation contains make_diag_full("pf-elbv2-lb-gwlb-no-scheme", "ERROR", name,
	"Properties.Scheme",
	"Scheme is set on a gateway load balancer; CreateLoadBalancer fails with \"Scheme is not supported for Gateway Load Balancers.\"",
	_pf_elbgs_fix, _pf_elbgs_url) if {
	some name in _pf_elb_lbs
	_pf_elb_lbtype(name) == "gateway"
	_pf_elb_has(name, "Scheme")
}
