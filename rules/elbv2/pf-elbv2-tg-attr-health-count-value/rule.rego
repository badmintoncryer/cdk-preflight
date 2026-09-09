package cdk_preflight

import rego.v1

_pf_elbghc_fix := "Use off, or a count of at least 1"

_pf_elbghc_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

violation contains make_diag_full("pf-elbv2-tg-attr-health-count-value", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Value", [p.index]),
	sprintf("'%s' is '%s'; the count is either 'off' or an integer of at least 1", [p.key, p.value]),
	_pf_elbghc_fix, _pf_elbghc_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	endswith(p.key, "minimum_healthy_targets.count")
	is_string(p.value)
	p.value != "off"
	not _pf_elbghc_ok(p.value)
}

_pf_elbghc_ok(v) if {
	n := _pf_elb_num(v)
	n >= 1
}
