package cdk_preflight

import rego.v1

_pf_elbltvm_fix := "Create the target group in the VPC the load balancer subnets belong to"

_pf_elbltvm_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html"

violation contains make_diag_full("pf-elbv2-listener-tg-vpc-match", "ERROR", p.tg,
	"Properties.VpcId",
	sprintf("The target group is in VPC '%s' but listener '%s' hangs off a load balancer in VPC '%s'", [tvpc, p.listener, lbvpc]),
	_pf_elbltvm_fix, _pf_elbltvm_url) if {
	some p in _pf_elb_listener_tgs
	lbvpc := _pf_elb_lb_vpc(_pf_elb_lb_of(p.listener))
	tvpc := resolve(p.tg, "Properties.VpcId")
	tvpc != lbvpc
}
