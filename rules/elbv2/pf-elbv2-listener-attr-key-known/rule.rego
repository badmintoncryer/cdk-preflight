package cdk_preflight

import rego.v1

_pf_elblak_fix := "Fix the attribute key (the service drops nothing silently, it rejects the call)"

_pf_elblak_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_ListenerAttribute.html"

violation contains make_diag_full("pf-elbv2-listener-attr-key-known", "ERROR", name,
	sprintf("Properties.ListenerAttributes.%d.Key", [p.index]),
	sprintf("'%s' is not a listener attribute key", [p.key]),
	_pf_elblak_fix, _pf_elblak_url) if {
	some name in _pf_elb_listeners
	some p in _pf_elb_pairs(name, "ListenerAttributes")
	not p.key in _pf_elb_lsattr_known
}
