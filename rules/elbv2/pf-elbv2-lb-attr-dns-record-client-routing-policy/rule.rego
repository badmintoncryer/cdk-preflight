package cdk_preflight

import rego.v1

_pf_elbadns_fix := "Use availability_zone_affinity, partial_availability_zone_affinity or any_availability_zone"

_pf_elbadns_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_LoadBalancerAttribute.html"

elbadns_allowed := {"availability_zone_affinity", "partial_availability_zone_affinity", "any_availability_zone"}

violation contains make_diag_full("pf-elbv2-lb-attr-dns-record-client-routing-policy", "ERROR", name,
	sprintf("Properties.LoadBalancerAttributes.%d.Value", [p.index]),
	sprintf("'%s' is not a valid value for '%s' (allowed: %v)", [p.value, p.key, elbadns_allowed]),
	_pf_elbadns_fix, _pf_elbadns_url) if {
	some name in _pf_elb_lbs
	some p in _pf_elb_pairs(name, "LoadBalancerAttributes")
	p.key == "dns_record.client_routing_policy"
	is_string(p.value)
	not p.value in elbadns_allowed
}
