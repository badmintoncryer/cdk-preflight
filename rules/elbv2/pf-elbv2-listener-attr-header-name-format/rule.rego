package cdk_preflight

import rego.v1

_pf_elblahn_fix := "Use RFC 7230 token characters only (letters, digits and !#$%&'*+-.^_`|~)"

_pf_elblahn_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_ListenerAttribute.html"

violation contains make_diag_full("pf-elbv2-listener-attr-header-name-format", "ERROR", name,
	sprintf("Properties.ListenerAttributes.%d.Value", [p.index]),
	sprintf("'%s' is not a valid HTTP header name for '%s'; a header name is made of RFC 7230 token characters", [p.value, p.key]),
	_pf_elblahn_fix, _pf_elblahn_url) if {
	some name in _pf_elb_listeners
	some p in _pf_elb_pairs(name, "ListenerAttributes")
	endswith(p.key, ".header_name")
	is_string(p.value)
	not regex.match("^[-!#$%&'*+.^_\u0060|~0-9A-Za-z]+$", p.value)
}
