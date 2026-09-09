package cdk_preflight

import rego.v1

_pf_elblaxc_fix := "Use nosniff, or drop the attribute to leave the header off"

_pf_elblaxc_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_ListenerAttribute.html"

elblaxc_allowed := {"nosniff"}

violation contains make_diag_full("pf-elbv2-listener-attr-x-content-type-options-value", "ERROR", name,
	sprintf("Properties.ListenerAttributes.%d.Value", [p.index]),
	sprintf("'%s' is not a valid value for '%s' (allowed: %v)", [p.value, p.key, elblaxc_allowed]),
	_pf_elblaxc_fix, _pf_elblaxc_url) if {
	some name in _pf_elb_listeners
	some p in _pf_elb_pairs(name, "ListenerAttributes")
	p.key == "routing.http.response.x_content_type_options.header_value"
	is_string(p.value)
	not p.value in elblaxc_allowed
}
