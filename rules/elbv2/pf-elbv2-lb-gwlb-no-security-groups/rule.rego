package cdk_preflight

import rego.v1

_pf_elbgsg_fix := "Drop SecurityGroups; filter traffic on the appliance targets instead"

_pf_elbgsg_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html"

violation contains make_diag_full("pf-elbv2-lb-gwlb-no-security-groups", "ERROR", name,
	"Properties.SecurityGroups",
	"SecurityGroups is set on a gateway load balancer; CreateLoadBalancer fails with \"Security Groups are not supported for Gateway Load Balancers.\"",
	_pf_elbgsg_fix, _pf_elbgsg_url) if {
	some name in _pf_elb_lbs
	_pf_elb_lbtype(name) == "gateway"
	_pf_elb_has(name, "SecurityGroups")
}
