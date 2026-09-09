package cdk_preflight

import rego.v1

_pf_elbastr_fix := "Set SessionTimeout to at most 604800 (7 days)"

_pf_elbastr_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_AuthenticateOidcActionConfig.html"

violation contains make_diag_full("pf-elbv2-action-session-timeout-range", "ERROR", name,
	sprintf("Properties.%s.%d.%s.SessionTimeout", [a.prop, a.index, cfg]),
	sprintf("The authentication session is set to %v seconds; the service takes 1 to 604800 (7 days)", [t]),
	_pf_elbastr_fix, _pf_elbastr_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	some cfg in _pf_elb_auth_configs
	oc := _pf_elb_oget(a.value, cfg)
	t := _pf_elb_num(_pf_elb_oget(oc, "SessionTimeout"))
	_pf_elb_outside(t, 1, 604800)
}
