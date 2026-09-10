package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-endpoint-dohfips-inbound-only", "ERROR", name,
	"Properties.Protocols",
	"the outbound endpoint declares DoH-FIPS; only inbound endpoints support it",
	"Use Do53 or DoH on an outbound endpoint",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverEndpoint.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverEndpoint")
	p := _pf_r53r_props(name)
	_pf_r53r_str(p, "Direction") == "OUTBOUND"
	"DoH-FIPS" in _pf_r53r_protos(p)
}
