package cdk_preflight

import rego.v1

_pf_elbgamv_fix := "Use on or off (not true/false)"

_pf_elbgamv_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

elbgamv_allowed := {"on", "off"}

violation contains make_diag_full("pf-elbv2-tg-attr-anomaly-mitigation-value", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Value", [p.index]),
	sprintf("'%s' is not a valid value for '%s' (allowed: %v)", [p.value, p.key, elbgamv_allowed]),
	_pf_elbgamv_fix, _pf_elbgamv_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	p.key == "load_balancing.algorithm.anomaly_mitigation"
	is_string(p.value)
	not p.value in elbgamv_allowed
}
