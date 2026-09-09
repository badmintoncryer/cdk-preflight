package cdk_preflight

import rego.v1

_pf_elbaxff_fix := "Use append, preserve or remove"

_pf_elbaxff_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancerAttribute.html"

elbaxff_allowed := {"append", "preserve", "remove"}

violation contains make_diag_full("pf-elbv2-lb-attr-xff-header-processing-mode", "ERROR", name,
	sprintf("Properties.LoadBalancerAttributes.%d.Value", [p.index]),
	sprintf("'%s' is not a valid value for '%s' (allowed: %v)", [p.value, p.key, elbaxff_allowed]),
	_pf_elbaxff_fix, _pf_elbaxff_url) if {
	some name in _pf_elb_lbs
	some p in _pf_elb_pairs(name, "LoadBalancerAttributes")
	p.key == "routing.http.xff_header_processing.mode"
	is_string(p.value)
	not p.value in elbaxff_allowed
}
