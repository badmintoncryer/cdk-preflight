package cdk_preflight

import rego.v1

_pf_elbaoua_fix := "Use deny, allow or authenticate"

_pf_elbaoua_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_AuthenticateOidcActionConfig.html"

violation contains make_diag_full("pf-elbv2-action-oidc-on-unauthenticated-values", "ERROR", name,
	sprintf("Properties.%s.%d.%s.OnUnauthenticatedRequest", [a.prop, a.index, cfg]),
	sprintf("OnUnauthenticatedRequest is '%s'; the service takes deny, allow or authenticate", [v]),
	_pf_elbaoua_fix, _pf_elbaoua_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	some cfg in _pf_elb_auth_configs
	oc := _pf_elb_oget(a.value, cfg)
	v := _pf_elb_oget(oc, "OnUnauthenticatedRequest")
	not v in {"deny", "allow", "authenticate"}
}
