package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-rule-system-forbids-endpoint-and-targetips", "ERROR", name,
	"Properties.ResolverEndpointId",
	"RuleType is SYSTEM but ResolverEndpointId is set; system rules take neither an endpoint nor target IPs",
	"Drop ResolverEndpointId, or use RuleType FORWARD",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverRule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRule")
	p := _pf_r53r_props(name)
	_pf_r53r_str(p, "RuleType") == "SYSTEM"
	_pf_r53r_has(p, "ResolverEndpointId")
}

violation contains make_diag_full("pf-route53resolver-rule-system-forbids-endpoint-and-targetips", "ERROR", name,
	"Properties.TargetIps",
	"RuleType is SYSTEM but TargetIps is set; system rules take neither an endpoint nor target IPs",
	"Drop TargetIps, or use RuleType FORWARD",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverRule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRule")
	p := _pf_r53r_props(name)
	_pf_r53r_str(p, "RuleType") == "SYSTEM"
	_pf_r53r_has(p, "TargetIps")
}
