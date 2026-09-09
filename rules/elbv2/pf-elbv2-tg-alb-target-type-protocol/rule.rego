package cdk_preflight

import rego.v1

_pf_elbtalb_fix := "Set Protocol to TCP for a target group with TargetType alb"

_pf_elbtalb_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-alb-target-type-protocol", "ERROR", name,
	"Properties.Protocol",
	sprintf("TargetType is 'alb' with Protocol '%s'; an ALB target is registered behind a network load balancer, so the protocol must be TCP", [p]),
	_pf_elbtalb_fix, _pf_elbtalb_url) if {
	some name in _pf_elb_tgs
	_pf_elb_tgtype(name) == "alb"
	p := _pf_elb_str(name, "Protocol")
	p != "TCP"
}
