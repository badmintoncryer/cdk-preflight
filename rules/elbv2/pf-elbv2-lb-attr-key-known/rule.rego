package cdk_preflight

import rego.v1

_pf_elbakk_fix := "Use a key from the LoadBalancerAttribute table (a typo is rejected, not ignored)"

_pf_elbakk_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancerAttribute.html"

violation contains make_diag_full("pf-elbv2-lb-attr-key-known", "ERROR", name,
	sprintf("Properties.LoadBalancerAttributes.%d.Key", [p.index]),
	sprintf("Load balancer attribute key '%s' is not recognized; ModifyLoadBalancerAttributes rejects unknown keys", [p.key]),
	_pf_elbakk_fix, _pf_elbakk_url) if {
	some name in _pf_elb_lbs
	some p in _pf_elb_pairs(name, "LoadBalancerAttributes")
	not p.key in _pf_elb_lbattr_known
}
