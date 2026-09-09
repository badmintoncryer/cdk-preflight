package cdk_preflight

import rego.v1

_pf_elbafwr_fix := "Set Weight on each target group of the action"

_pf_elbafwr_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_TargetGroupTuple.html"

violation contains make_diag_full("pf-elbv2-action-forward-weight-required-multi", "ERROR", name,
	sprintf("Properties.%s.%d.ForwardConfig.TargetGroups.%d.Weight", [a.prop, a.index, i]),
	"The forward action spreads over several target groups but this one has no Weight; the service needs a weight on each to split the traffic",
	_pf_elbafwr_fix, _pf_elbafwr_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	tgs := _pf_elb_fwd_tgs(a.value)
	count(tgs) > 1
	some i, tg in tgs
	not _pf_elb_ohas(tg, "Weight")
}
