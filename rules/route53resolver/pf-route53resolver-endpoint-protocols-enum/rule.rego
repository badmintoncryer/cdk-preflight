package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-endpoint-protocols-enum", "ERROR", name,
	"Properties.Protocols",
	sprintf("Protocols contains '%s'; Route 53 Resolver only accepts Do53, DoH and DoH-FIPS", [x]),
	"Use Do53, DoH or DoH-FIPS",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverEndpoint.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverEndpoint")
	p := _pf_r53r_props(name)
	some x in _pf_r53r_arr(p, "Protocols")
	is_string(x)
	not x in {"Do53", "DoH", "DoH-FIPS"}
}
