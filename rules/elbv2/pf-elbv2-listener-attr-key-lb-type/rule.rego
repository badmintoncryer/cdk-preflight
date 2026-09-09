package cdk_preflight

import rego.v1

_pf_elblalt_fix := "Move the attribute to a listener of the load balancer type that supports it"

_pf_elblalt_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_ListenerAttribute.html"

violation contains make_diag_full("pf-elbv2-listener-attr-key-lb-type", "ERROR", name,
	sprintf("Properties.ListenerAttributes.%d.Key", [p.index]),
	sprintf("'%s' is not supported on a listener of a %s load balancer", [p.key, lbt]),
	_pf_elblalt_fix, _pf_elblalt_url) if {
	some name in _pf_elb_listeners
	some p in _pf_elb_pairs(name, "ListenerAttributes")
	p.key in _pf_elb_lsattr_known
	lbt := _pf_elb_listener_lbtype(name)
	not p.key in _pf_elb_lsattr_for[lbt]
}
