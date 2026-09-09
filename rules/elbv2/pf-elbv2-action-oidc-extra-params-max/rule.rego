package cdk_preflight

import rego.v1

_pf_elbaoep_fix := "Keep AuthenticationRequestExtraParams to ten entries"

_pf_elbaoep_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_AuthenticateOidcActionConfig.html"

violation contains make_diag_full("pf-elbv2-action-oidc-extra-params-max", "ERROR", name,
	sprintf("Properties.%s.%d.%s.AuthenticationRequestExtraParams", [a.prop, a.index, cfg]),
	sprintf("The action passes %d extra authentication parameters; the service takes at most 10", [n]),
	_pf_elbaoep_fix, _pf_elbaoep_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	some cfg in _pf_elb_auth_configs
	oc := _pf_elb_oget(a.value, cfg)
	ps := _pf_elb_oget(oc, "AuthenticationRequestExtraParams")
	is_object(ps)
	n := count(ps)
	n > 10
}
