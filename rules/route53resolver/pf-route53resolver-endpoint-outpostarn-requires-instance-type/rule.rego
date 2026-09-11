package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-endpoint-outpostarn-requires-instance-type", "ERROR", name,
	"Properties.OutpostArn",
	"OutpostArn is set but PreferredInstanceType is missing; both are required for an Outpost-local endpoint",
	"Add PreferredInstanceType, or drop OutpostArn",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverEndpoint.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverEndpoint")
	p := _pf_r53r_props(name)
	_pf_r53r_has(p, "OutpostArn")
	not _pf_r53r_has(p, "PreferredInstanceType")
}
