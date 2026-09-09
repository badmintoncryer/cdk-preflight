package cdk_preflight

import rego.v1

_pf_elbafst_fix := "Drop TargetGroupStickinessConfig, or move the action to a TCP listener"

_pf_elbafst_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-listeners.html"

violation contains make_diag_full("pf-elbv2-action-forward-stickiness-tls", "ERROR", name,
	sprintf("Properties.%s.%d.ForwardConfig.TargetGroupStickinessConfig.Enabled", [a.prop, a.index]),
	"Target group stickiness is enabled on a TLS listener, which terminates the connection and cannot pin it to a target group",
	_pf_elbafst_fix, _pf_elbafst_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	fc := _pf_elb_oget(a.value, "ForwardConfig")
	sc := _pf_elb_oget(fc, "TargetGroupStickinessConfig")
	object.get(sc, "Enabled", false) in _pf_elb_true
	_pf_elb_listener_proto(name) == "TLS"
}
