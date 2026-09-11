package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-rule-targetips-address-family-exclusive", "ERROR", name,
	"Properties.TargetIps",
	"TargetIps mixes IPv4 (Ip) and IPv6 (Ipv6) addresses; a Resolver rule takes one address family",
	"Use either Ip or Ipv6 for every target, not both",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverRule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRule")
	p := _pf_r53r_props(name)
	tips := _pf_r53r_arr(p, "TargetIps")
	count([1 | some t in tips; _pf_r53r_has(t, "Ip")]) > 0
	count([1 | some t in tips; _pf_r53r_has(t, "Ipv6")]) > 0
}
