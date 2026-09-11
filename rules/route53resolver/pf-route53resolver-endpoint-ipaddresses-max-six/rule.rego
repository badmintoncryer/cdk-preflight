package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-endpoint-ipaddresses-max-six", "ERROR", name,
	"Properties.IpAddresses",
	sprintf("the endpoint declares %d IP addresses; Route 53 Resolver allows at most 6 per endpoint", [n]),
	"Keep at most 6 entries in IpAddresses, or split across endpoints",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DNSLimitations.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverEndpoint")
	p := _pf_r53r_props(name)
	n := count(_pf_r53r_ips(p))
	n > 6
}
