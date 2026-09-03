package cdk_preflight

import rego.v1

# Allow-sets verbatim from the two benched service errors.
_pf_elblpt_allow := {"application": {"HTTP", "HTTPS"}, "network": {"TCP", "QUIC", "TCP_QUIC", "UDP", "TCP_UDP", "TLS"}}

_pf_elblpt_type(lb) := t if {
	props := input.resources[lb].properties
	is_object(props)
	t := object.get(props, "Type", "application")
}

violation contains make_diag_full("pf-elbv2-listener-protocol-lb-type", "ERROR", name,
	"Properties.Protocol",
	sprintf("Listener protocol '%s' is not valid for a %s load balancer (allowed: %v)", [proto, t, allow]),
	"Use HTTP/HTTPS on application LBs and TCP/UDP/TLS/QUIC variants on network LBs",
	"https://docs.aws.amazon.com/elasticloadbalancing/latest/APIReference/API_CreateListener.html") if {
	some name in resources_of_type("AWS::ElasticLoadBalancingV2::Listener")
	lb := resolve(name, "Properties.LoadBalancerArn")
	lb in resources_of_type("AWS::ElasticLoadBalancingV2::LoadBalancer")
	t := _pf_elblpt_type(lb)
	allow := _pf_elblpt_allow[t]
	proto := resolve(name, "Properties.Protocol")
	is_string(proto)
	not proto in allow
}
