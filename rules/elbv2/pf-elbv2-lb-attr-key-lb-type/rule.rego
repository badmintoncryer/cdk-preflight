package cdk_preflight

import rego.v1

_pf_elbakt_fix := "Keep type-only attributes on the load balancer type that supports them"

_pf_elbakt_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancerAttribute.html"

violation contains make_diag_full("pf-elbv2-lb-attr-key-lb-type", "ERROR", name,
	sprintf("Properties.LoadBalancerAttributes.%d.Key", [p.index]),
	sprintf("Attribute key '%s' is not supported on a %s load balancer; ModifyLoadBalancerAttributes reports it as not recognized", [p.key, t]),
	_pf_elbakt_fix, _pf_elbakt_url) if {
	some name in _pf_elb_lbs
	some p in _pf_elb_pairs(name, "LoadBalancerAttributes")
	t := _pf_elb_lbtype(name)
	t in {"application", "network"}
	p.key in _pf_elb_lbattr_known
	not p.key in _pf_elb_lbattr_for[t]
}
