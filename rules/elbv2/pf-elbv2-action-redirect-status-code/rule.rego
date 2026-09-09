package cdk_preflight

import rego.v1

_pf_elbarsc_fix := "Use HTTP_301 (permanent) or HTTP_302 (temporary)"

_pf_elbarsc_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RedirectActionConfig.html"

violation contains make_diag_full("pf-elbv2-action-redirect-status-code", "ERROR", name,
	sprintf("Properties.%s.%d.RedirectConfig.StatusCode", [a.prop, a.index]),
	sprintf("The redirect answers with '%v'; a listener redirect is either HTTP_301 or HTTP_302", [sc]),
	_pf_elbarsc_fix, _pf_elbarsc_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	rc := _pf_elb_oget(a.value, "RedirectConfig")
	sc := _pf_elb_oget(rc, "StatusCode")
	not sc in {"HTTP_301", "HTTP_302"}
}
