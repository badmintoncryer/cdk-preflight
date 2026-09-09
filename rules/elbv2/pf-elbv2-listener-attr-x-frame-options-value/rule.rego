package cdk_preflight

import rego.v1

_pf_elblaxf_fix := "Use DENY or SAMEORIGIN (the listener does not serve ALLOW-FROM)"

_pf_elblaxf_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_ListenerAttribute.html"

elblaxf_allowed := {"DENY", "SAMEORIGIN"}

violation contains make_diag_full("pf-elbv2-listener-attr-x-frame-options-value", "ERROR", name,
	sprintf("Properties.ListenerAttributes.%d.Value", [p.index]),
	sprintf("'%s' is not a valid value for '%s' (allowed: %v)", [p.value, p.key, elblaxf_allowed]),
	_pf_elblaxf_fix, _pf_elblaxf_url) if {
	some name in _pf_elb_listeners
	some p in _pf_elb_pairs(name, "ListenerAttributes")
	p.key == "routing.http.response.x_frame_options.header_value"
	is_string(p.value)
	not p.value in elblaxf_allowed
}
