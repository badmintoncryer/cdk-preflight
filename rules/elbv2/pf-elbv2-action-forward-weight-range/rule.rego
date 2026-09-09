package cdk_preflight

import rego.v1

_pf_elbafwt_fix := "Give every target group a weight in 0-999"

_pf_elbafwt_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupTuple.html"

violation contains make_diag_full("pf-elbv2-action-forward-weight-range", "ERROR", name,
	sprintf("Properties.%s.%d.ForwardConfig.TargetGroups.%d.Weight", [a.prop, a.index, i]),
	sprintf("The target group weight is %v; a weight runs from 0 to 999", [w]),
	_pf_elbafwt_fix, _pf_elbafwt_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	tgs := _pf_elb_fwd_tgs(a.value)
	some i, tg in tgs
	w := _pf_elb_num(_pf_elb_oget(tg, "Weight"))
	_pf_elb_outside(w, 0, 999)
}
