package cdk_preflight

import rego.v1

_pf_elbarpl_fix := "Start Path with /"

_pf_elbarpl_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_RedirectActionConfig.html"

violation contains make_diag_full("pf-elbv2-action-redirect-path-leading-slash", "ERROR", name,
	sprintf("Properties.%s.%d.RedirectConfig.Path", [a.prop, a.index]),
	sprintf("The redirect path is '%s'; the service takes an absolute path that starts with /", [p]),
	_pf_elbarpl_fix, _pf_elbarpl_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	rc := _pf_elb_oget(a.value, "RedirectConfig")
	p := _pf_elb_oget(rc, "Path")
	is_string(p)
	not startswith(p, "/")
}
