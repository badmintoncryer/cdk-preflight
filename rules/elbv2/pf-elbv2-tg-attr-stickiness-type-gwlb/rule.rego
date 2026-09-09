package cdk_preflight

import rego.v1

_pf_elbgstg_fix := "Use source_ip_dest_ip or source_ip_dest_ip_proto on a GENEVE target group"

_pf_elbgstg_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

violation contains make_diag_full("pf-elbv2-tg-attr-stickiness-type-gwlb", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Value", [p.index]),
	sprintf("stickiness.type '%s' on a GENEVE target group; a Gateway Load Balancer only supports source_ip_dest_ip and source_ip_dest_ip_proto", [p.value]),
	_pf_elbgstg_fix, _pf_elbgstg_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	_pf_elb_tgfamily(name) == "gateway"
	p.key == "stickiness.type"
	is_string(p.value)
	not p.value in {"source_ip_dest_ip", "source_ip_dest_ip_proto"}
}
