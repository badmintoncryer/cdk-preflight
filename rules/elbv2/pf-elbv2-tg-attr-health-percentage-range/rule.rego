package cdk_preflight

import rego.v1

_pf_elbghp_fix := "Use off, or a percentage between 1 and 100"

_pf_elbghp_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupAttribute.html"

violation contains make_diag_full("pf-elbv2-tg-attr-health-percentage-range", "ERROR", name,
	sprintf("Properties.TargetGroupAttributes.%d.Value", [p.index]),
	sprintf("'%s' is '%s'; the percentage is either 'off' or between 1 and 100", [p.key, p.value]),
	_pf_elbghp_fix, _pf_elbghp_url) if {
	some name in _pf_elb_tgs
	some p in _pf_elb_pairs(name, "TargetGroupAttributes")
	endswith(p.key, "minimum_healthy_targets.percentage")
	is_string(p.value)
	p.value != "off"
	not _pf_elbghp_ok(p.value)
}

_pf_elbghp_ok(v) if {
	n := _pf_elb_num(v)
	n >= 1
	n <= 100
}
