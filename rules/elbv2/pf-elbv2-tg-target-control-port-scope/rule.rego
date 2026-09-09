package cdk_preflight

import rego.v1

_pf_elbtcp_fix := "Drop TargetControlPort unless the target group is HTTP/HTTPS with instance or ip targets"

_pf_elbtcp_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateTargetGroup.html"

violation contains make_diag_full("pf-elbv2-tg-target-control-port-scope", "ERROR", name,
	"Properties.TargetControlPort",
	sprintf("TargetControlPort is set on a %s target group with target type '%s'; the target optimizer only supports HTTP/HTTPS target groups of instance or ip targets", [p, t]),
	_pf_elbtcp_fix, _pf_elbtcp_url) if {
	some name in _pf_elb_tgs
	_pf_elb_has(name, "TargetControlPort")
	p := object.get(_pf_elb_props(name), "Protocol", "none")
	t := _pf_elb_tgtype(name)
	not _pf_elbtcp_ok(p, t)
}

_pf_elbtcp_ok(p, t) if {
	p in _pf_elb_alb_protocols
	t in {"instance", "ip"}
}
