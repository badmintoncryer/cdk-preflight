package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrule-domainlist-threat-exclusive", "ERROR", name,
	sprintf("Properties.FirewallRules[%d]", [i]),
	"the rule sets both FirewallDomainListId and DnsThreatProtection; they are mutually exclusive",
	"Split them into two rules",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateFirewallRule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
	some i, r in _pf_r53r_frules(name)
	_pf_r53r_has(r, "FirewallDomainListId")
	_pf_r53r_has(r, "DnsThreatProtection")
}
