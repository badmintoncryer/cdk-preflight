package cdk_preflight

import rego.v1

_pf_elbgstr_fix := "Drop send_tcp_reset.on_* unless the target group protocol is GENEVE"

_pf_elbgstr_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

violation contains make_diag_full("pf-elbv2-tg-attr-send-tcp-reset-gwlb-only", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Key", [p.index]),
	sprintf("'%s' is set on a %s target group; the TCP reset attributes are only supported by Gateway Load Balancers", [p.key, f]),
	_pf_elbgstr_fix, _pf_elbgstr_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	startswith(p.key, "send_tcp_reset.")
	f := _pf_elb_tgfamily(name)
	f != "gateway"
}
