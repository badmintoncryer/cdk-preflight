package cdk_preflight

import rego.v1

_pf_elbtgsl_fix := "Give each load balancer its own target group (the quota cannot be raised)"

_pf_elbtgsl_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-limits.html"

violation contains make_diag_full("pf-elbv2-tg-single-load-balancer", "ERROR", g,
	"Properties",
	sprintf("The target group is used by %d load balancers; a target group can only be associated with one", [count(lbs)]),
	_pf_elbtgsl_fix, _pf_elbtgsl_url) if {
	some g in _pf_elb_tgs
	lbs := {lb |
		some p in _pf_elb_listener_tgs
		p.tg == g
		lb := _pf_elb_lb_of(p.listener)
	}
	count(lbs) > 1
}
