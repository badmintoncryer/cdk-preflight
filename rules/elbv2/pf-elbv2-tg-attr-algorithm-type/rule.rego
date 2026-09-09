package cdk_preflight

import rego.v1

_pf_elbgalg_fix := "Use round_robin, least_outstanding_requests or weighted_random"

_pf_elbgalg_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

elbgalg_allowed := {"round_robin", "least_outstanding_requests", "weighted_random"}

violation contains make_diag_full("pf-elbv2-tg-attr-algorithm-type", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Value", [p.index]),
	sprintf("'%s' is not a valid value for '%s' (allowed: %v)", [p.value, p.key, elbgalg_allowed]),
	_pf_elbgalg_fix, _pf_elbgalg_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	p.key == "load_balancing.algorithm.type"
	is_string(p.value)
	not p.value in elbgalg_allowed
}
