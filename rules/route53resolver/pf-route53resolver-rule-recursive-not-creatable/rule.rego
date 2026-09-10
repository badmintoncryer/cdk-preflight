package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-rule-recursive-not-creatable", "ERROR", name,
	"Properties.RuleType",
	"RuleType is RECURSIVE; only Route 53 Resolver itself creates recursive rules",
	"Use FORWARD, SYSTEM or DELEGATE",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverRule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRule")
	p := _pf_r53r_props(name)
	_pf_r53r_str(p, "RuleType") == "RECURSIVE"
}
