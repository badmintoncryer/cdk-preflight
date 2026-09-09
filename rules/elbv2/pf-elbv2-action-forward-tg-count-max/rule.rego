package cdk_preflight

import rego.v1

_pf_elbaftc_fix := "Forward to five target groups or fewer (the quota cannot be raised)"

_pf_elbaftc_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-limits.html"

violation contains make_diag_full("pf-elbv2-action-forward-tg-count-max", "ERROR", name,
	sprintf("Properties.%s.%d.ForwardConfig.TargetGroups", [a.prop, a.index]),
	sprintf("The forward action lists %d target groups; a single action takes at most 5", [n]),
	_pf_elbaftc_fix, _pf_elbaftc_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	tgs := _pf_elb_fwd_tgs(a.value)
	n := count(tgs)
	n > 5
}
