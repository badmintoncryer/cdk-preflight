package cdk_preflight

import rego.v1

_pf_elblase_fix := "Use \"true\" or \"false\""

_pf_elblase_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_ListenerAttribute.html"

elblase_allowed := {"true", "false"}

violation contains make_diag_full("pf-elbv2-listener-attr-server-enabled-value", "ERROR", name,
	sprintf("Properties.ListenerAttributes.%d.Value", [p.index]),
	sprintf("'%s' is not a valid value for '%s' (allowed: %v)", [p.value, p.key, elblase_allowed]),
	_pf_elblase_fix, _pf_elblase_url) if {
	some name in _pf_elb_listeners
	some p in _pf_elb_pairs(name, "ListenerAttributes")
	p.key == "routing.http.response.server.enabled"
	is_string(p.value)
	not p.value in elblase_allowed
}
