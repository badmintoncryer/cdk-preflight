package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrule-match-source-required", "ERROR", name,
	sprintf("Properties.FirewallRules[%d]", [i]),
	"the rule sets none of FirewallDomainListId, DnsThreatProtection and FirewallRuleType",
	"Point the rule at a domain list, a threat detector or a managed rule type",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateFirewallRule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
	some i, r in _pf_r53r_frules(name)
	count(_pf_r53r_match_used(r)) == 0
}
