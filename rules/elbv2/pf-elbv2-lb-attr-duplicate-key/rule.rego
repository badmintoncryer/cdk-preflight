package cdk_preflight

import rego.v1

_pf_elbadup_fix := "Keep one entry per attribute key"

_pf_elbadup_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancerAttribute.html"

violation contains make_diag_full("pf-elbv2-lb-attr-duplicate-key", "ERROR", name,
	"Properties.LoadBalancerAttributes",
	sprintf("Attribute key '%s' is specified more than once; ModifyLoadBalancerAttributes fails with \"Attribute key '%s' has been specified more than once\"", [k, k]),
	_pf_elbadup_fix, _pf_elbadup_url) if {
	some name in _pf_elb_lbs
	keys := [x.key | some x in _pf_elb_pairs(name, "LoadBalancerAttributes")]
	some k in keys
	count([x | some x in keys; x == k]) > 1
}
