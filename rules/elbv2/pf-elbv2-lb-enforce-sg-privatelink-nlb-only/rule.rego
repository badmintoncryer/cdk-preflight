package cdk_preflight

import rego.v1

_pf_elbepl_fix := "Drop EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic, or make this a network load balancer"

_pf_elbepl_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html"

violation contains make_diag_full("pf-elbv2-lb-enforce-sg-privatelink-nlb-only", "ERROR", name,
	"Properties.EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic",
	sprintf("EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic is set on a %s load balancer; it only applies to a network load balancer that has security groups", [t]),
	_pf_elbepl_fix, _pf_elbepl_url) if {
	some name in _pf_elb_lbs
	t := _pf_elb_lbtype(name)
	t != "network"
	_pf_elb_has(name, "EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic")
}
