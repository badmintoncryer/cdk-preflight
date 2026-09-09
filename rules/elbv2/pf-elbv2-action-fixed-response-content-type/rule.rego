package cdk_preflight

import rego.v1

_pf_elbafct_fix := "Use text/plain, text/css, text/html, application/javascript or application/json"

_pf_elbafct_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_FixedResponseActionConfig.html"

_pf_elbafct_types := {"text/plain", "text/css", "text/html", "application/javascript", "application/json"}

violation contains make_diag_full("pf-elbv2-action-fixed-response-content-type", "ERROR", name,
	sprintf("Properties.%s.%d.FixedResponseConfig.ContentType", [a.prop, a.index]),
	sprintf("The fixed response is served as '%s'; a listener only serves text/plain, text/css, text/html, application/javascript or application/json", [ct]),
	_pf_elbafct_fix, _pf_elbafct_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	fr := _pf_elb_oget(a.value, "FixedResponseConfig")
	ct := _pf_elb_oget(fr, "ContentType")
	not ct in _pf_elbafct_types
}
