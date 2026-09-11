package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-rule-forward-requires-endpoint-and-targetips", "ERROR", name,
	"Properties.ResolverEndpointId",
	"RuleType is FORWARD but ResolverEndpointId is missing",
	"Point ResolverEndpointId at an outbound Resolver endpoint",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverRule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRule")
	p := _pf_r53r_props(name)
	_pf_r53r_str(p, "RuleType") == "FORWARD"
	not _pf_r53r_has(p, "ResolverEndpointId")
}

violation contains make_diag_full("pf-route53resolver-rule-forward-requires-endpoint-and-targetips", "ERROR", name,
	"Properties.TargetIps",
	"RuleType is FORWARD but TargetIps is missing",
	"Add the target name server addresses to TargetIps",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverRule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRule")
	p := _pf_r53r_props(name)
	_pf_r53r_str(p, "RuleType") == "FORWARD"
	not _pf_r53r_has(p, "TargetIps")
}
