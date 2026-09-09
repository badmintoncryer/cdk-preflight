package cdk_preflight

import rego.v1

_pf_elblaah_fix := "Move the authenticate action to an HTTPS listener"

_pf_elblaah_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html"

violation contains make_diag_full("pf-elbv2-listener-auth-action-https-only", "ERROR", name,
	sprintf("Properties.DefaultActions.%d.Type", [a.index]),
	sprintf("An '%s' action is on a %s listener; the OIDC and Cognito flows need TLS, so they are only accepted on an HTTPS listener", [t, proto]),
	_pf_elblaah_fix, _pf_elblaah_url) if {
	some name in _pf_elb_listeners
	some a in _pf_elb_actions(name, "DefaultActions")
	t := object.get(a.value, "Type", "")
	t in {"authenticate-cognito", "authenticate-oidc"}
	proto := object.get(_pf_elb_props(name), "Protocol", "GENEVE")
	proto != "HTTPS"
}
