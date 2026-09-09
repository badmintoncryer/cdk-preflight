package cdk_preflight

import rego.v1

_pf_elbadm_fix := "Use monitor, defensive or strictest"

_pf_elbadm_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancerAttribute.html"

elbadm_allowed := {"monitor", "defensive", "strictest"}

violation contains make_diag_full("pf-elbv2-lb-attr-desync-mitigation-mode", "ERROR", name,
	sprintf("Properties.LoadBalancerAttributes.%d.Value", [p.index]),
	sprintf("'%s' is not a valid value for '%s' (allowed: %v)", [p.value, p.key, elbadm_allowed]),
	_pf_elbadm_fix, _pf_elbadm_url) if {
	some name in _pf_elb_lbs
	some p in _pf_elb_pairs(name, "LoadBalancerAttributes")
	p.key == "routing.http.desync_mitigation_mode"
	is_string(p.value)
	not p.value in elbadm_allowed
}
