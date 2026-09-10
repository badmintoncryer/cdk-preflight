package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-endpoint-type-ipv4-address-family", "ERROR", name,
	"Properties.IpAddresses",
	"ResolverEndpointType is IPV4 but IpAddresses declares an Ipv6 address",
	"Drop the Ipv6 entries, or set ResolverEndpointType to IPV6 or DUALSTACK",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverEndpoint.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverEndpoint")
	p := _pf_r53r_props(name)
	_pf_r53r_str(p, "ResolverEndpointType") == "IPV4"
	some ip in _pf_r53r_ips(p)
	_pf_r53r_has(ip, "Ipv6")
}
