package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-endpoint-type-ipv6-address-family", "ERROR", name,
	"Properties.IpAddresses",
	"ResolverEndpointType is IPV6 but IpAddresses declares an Ip (IPv4) address",
	"Drop the Ip entries, or set ResolverEndpointType to IPV4 or DUALSTACK",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverEndpoint.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverEndpoint")
	p := _pf_r53r_props(name)
	_pf_r53r_str(p, "ResolverEndpointType") == "IPV6"
	some ip in _pf_r53r_ips(p)
	_pf_r53r_has(ip, "Ip")
}
