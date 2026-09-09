package cdk_preflight

import rego.v1

_pf_elbagw_fix := "On a Gateway Load Balancer keep deletion_protection.enabled and load_balancing.cross_zone.enabled only"

_pf_elbagw_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancerAttribute.html"

violation contains make_diag_full("pf-elbv2-lb-attr-alb-only-on-gwlb", "ERROR", name,
	sprintf("Properties.LoadBalancerAttributes.%d.Key", [p.index]),
	sprintf("Attribute key '%s' is set on a gateway load balancer, which only supports deletion_protection.enabled and load_balancing.cross_zone.enabled", [p.key]),
	_pf_elbagw_fix, _pf_elbagw_url) if {
	some name in _pf_elb_lbs
	some p in _pf_elb_pairs(name, "LoadBalancerAttributes")
	_pf_elb_lbtype(name) == "gateway"
	p.key in _pf_elb_lbattr_known
	not p.key in _pf_elb_lbattr_common
}
