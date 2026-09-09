package cdk_preflight

import rego.v1

_pf_elbafta_fix := "Drop TargetGroupArn and keep the target groups in ForwardConfig"

_pf_elbafta_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_Action.html"

_pf_elbafta_ok(arn, tgs) if {
	count(tgs) == 1
	_pf_elb_ref(object.get(tgs[0], "TargetGroupArn", null)) == arn
}

violation contains make_diag_full("pf-elbv2-action-forward-tgarn-conflict", "ERROR", name,
	sprintf("Properties.%s.%d.ForwardConfig", [a.prop, a.index]),
	"The action sets both TargetGroupArn and ForwardConfig; when both are present ForwardConfig has to hold exactly that one target group",
	_pf_elbafta_fix, _pf_elbafta_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	tgs := _pf_elb_fwd_tgs(a.value)
	count(tgs) > 0
	arn := _pf_elb_ref(_pf_elb_oget(a.value, "TargetGroupArn"))
	not _pf_elbafta_ok(arn, tgs)
}
