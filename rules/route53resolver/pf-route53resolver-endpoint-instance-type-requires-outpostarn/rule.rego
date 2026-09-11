package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-endpoint-instance-type-requires-outpostarn", "ERROR", name,
	"Properties.PreferredInstanceType",
	"PreferredInstanceType is set but OutpostArn is missing; it is only accepted for Outpost-local endpoints",
	"Add OutpostArn, or drop PreferredInstanceType",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverEndpoint.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverEndpoint")
	p := _pf_r53r_props(name)
	_pf_r53r_has(p, "PreferredInstanceType")
	not _pf_r53r_has(p, "OutpostArn")
}
