package cdk_preflight

import rego.v1

_pf_elbgcz_fix := "Use true, false or use_load_balancer_configuration"

_pf_elbgcz_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

elbgcz_allowed := {"true", "false", "use_load_balancer_configuration"}

violation contains make_diag_full("pf-elbv2-tg-attr-cross-zone-value", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Value", [p.index]),
	sprintf("'%s' is not a valid value for '%s' (allowed: %v)", [p.value, p.key, elbgcz_allowed]),
	_pf_elbgcz_fix, _pf_elbgcz_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	p.key == "load_balancing.cross_zone.enabled"
	is_string(p.value)
	not p.value in elbgcz_allowed
}
