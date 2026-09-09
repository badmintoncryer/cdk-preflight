package cdk_preflight

import rego.v1

_pf_elbta1_fix := "Register one Application Load Balancer per target group (this quota cannot be raised)"

_pf_elbta1_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-alb-single-target", "ERROR", name,
	"Properties.Targets",
	sprintf("%d targets are registered on a target group of type alb; only one Application Load Balancer can be registered", [n]),
	_pf_elbta1_fix, _pf_elbta1_url) if {
	some name in _pf_elb_tgs
	_pf_elb_tgtype(name) == "alb"
	n := count(flatten_list(name, "Properties.Targets"))
	n > 1
}
