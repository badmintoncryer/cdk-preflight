package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-ruleassociation-duplicate-rule-vpc", "ERROR", name,
	"Properties.ResolverRuleId",
	"another ResolverRuleAssociation in this template already associates the same rule with the same VPC",
	"Keep one association per rule and VPC",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_AssociateResolverRule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRuleAssociation")
	p := _pf_r53r_props(name)
	k := sprintf("%s|%s", [_pf_r53r_key(p, "ResolverRuleId"), _pf_r53r_key(p, "VPCId")])
	dup := [1 |
		some o in resources_of_type("AWS::Route53Resolver::ResolverRuleAssociation")
		q := _pf_r53r_props(o)
		sprintf("%s|%s", [_pf_r53r_key(q, "ResolverRuleId"), _pf_r53r_key(q, "VPCId")]) == k
	]
	count(dup) > 1
}
