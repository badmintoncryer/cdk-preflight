package cdk_preflight

import rego.v1

_pf_elbaoeh_fix := "Write the endpoint as https://host/path"

_pf_elbaoeh_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_AuthenticateOidcActionConfig.html"

_pf_elbaoeh_keys := {"Issuer", "AuthorizationEndpoint", "TokenEndpoint", "UserInfoEndpoint"}

violation contains make_diag_full("pf-elbv2-action-oidc-endpoint-https", "ERROR", name,
	sprintf("Properties.%s.%d.AuthenticateOidcConfig.%s", [a.prop, a.index, k]),
	sprintf("The OIDC %s is '%s'; the service needs a full URL including the https:// protocol", [k, v]),
	_pf_elbaoeh_fix, _pf_elbaoeh_url) if {
	some a in _pf_elb_all_actions
	name := a.name
	oc := _pf_elb_oget(a.value, "AuthenticateOidcConfig")
	some k in _pf_elbaoeh_keys
	v := _pf_elb_oget(oc, k)
	is_string(v)
	not startswith(v, "https://")
}
