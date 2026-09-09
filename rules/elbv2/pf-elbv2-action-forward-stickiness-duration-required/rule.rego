package cdk_preflight

import rego.v1

_pf_elbafsr_fix := "Add DurationSeconds next to Enabled: true"

_pf_elbafsr_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupStickinessConfig.html"

violation contains make_diag_full("pf-elbv2-action-forward-stickiness-duration-required", "ERROR", name,
	sprintf("Properties.%s.%d.ForwardConfig.TargetGroupStickinessConfig.DurationSeconds", [a.prop, a.index]),
	"Target group stickiness is enabled without DurationSeconds; the service has no default to fall back on",
	_pf_elbafsr_fix, _pf_elbafsr_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	fc := _pf_elb_oget(a.value, "ForwardConfig")
	sc := _pf_elb_oget(fc, "TargetGroupStickinessConfig")
	object.get(sc, "Enabled", false) in _pf_elb_true
	not _pf_elb_ohas(sc, "DurationSeconds")
}
