package cdk_preflight

import rego.v1

_pf_elbeps_fix := "Give the network load balancer SecurityGroups, or drop the setting"

_pf_elbeps_url := "https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateLoadBalancer.html"

violation contains make_diag_full("pf-elbv2-lb-enforce-sg-privatelink-requires-sg", "ERROR", name,
	"Properties.EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic",
	"EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic is set on a load balancer that has no SecurityGroups; there are no inbound rules to enforce",
	_pf_elbeps_fix, _pf_elbeps_url) if {
	some name in _pf_elb_lbs
	_pf_elb_has(name, "EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic")
	_pf_elb_absent(name, "SecurityGroups")
}
