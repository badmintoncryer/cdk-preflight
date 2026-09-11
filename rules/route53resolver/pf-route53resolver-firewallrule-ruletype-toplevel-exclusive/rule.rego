package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrule-ruletype-toplevel-exclusive", "ERROR", name,
	sprintf("Properties.FirewallRules[%d]", [i]),
	sprintf("the rule sets FirewallRuleType together with %s; they are mutually exclusive", [k]),
	"Split them into two rules",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateFirewallRule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
	some i, r in _pf_r53r_frules(name)
	_pf_r53r_has(r, "FirewallRuleType")
	some k in {"FirewallDomainListId", "DnsThreatProtection"}
	_pf_r53r_has(r, k)
}
