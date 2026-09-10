package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-endpoint-subnet-address-family", "ERROR", name,
	"Properties.ResolverEndpointType",
	sprintf("ResolverEndpointType is %s but subnet %s has no Ipv6CidrBlock", [t, s]),
	"Give the subnet an IPv6 CIDR, or use ResolverEndpointType IPV4",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-forwarding-inbound-queries.html#resolver-forwarding-inbound-queries-values") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverEndpoint")
	p := _pf_r53r_props(name)
	t := _pf_r53r_str(p, "ResolverEndpointType")
	t in {"IPV6", "DUALSTACK"}
	some s in _pf_r53r_subnets(p)
	not _pf_r53r_has(_pf_r53r_props(s), "Ipv6CidrBlock")
}
