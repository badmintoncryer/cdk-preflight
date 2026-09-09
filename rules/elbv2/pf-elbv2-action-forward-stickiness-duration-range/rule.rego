package cdk_preflight

import rego.v1

_pf_elbafsd_fix := "Set DurationSeconds to at most 604800 (7 days)"

_pf_elbafsd_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupStickinessConfig.html"

violation contains make_diag_full("pf-elbv2-action-forward-stickiness-duration-range", "ERROR", name,
	sprintf("Properties.%s.%d.ForwardConfig.TargetGroupStickinessConfig.DurationSeconds", [a.prop, a.index]),
	sprintf("Target group stickiness is set to %v seconds; the service takes 1 to 604800 (7 days)", [d]),
	_pf_elbafsd_fix, _pf_elbafsd_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	fc := _pf_elb_oget(a.value, "ForwardConfig")
	sc := _pf_elb_oget(fc, "TargetGroupStickinessConfig")
	d := _pf_elb_num(_pf_elb_oget(sc, "DurationSeconds"))
	_pf_elb_outside(d, 1, 604800)
}
