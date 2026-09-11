package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrule-domainlist-qtype-unique", "ERROR", name,
	sprintf("Properties.FirewallRules[%d]", [i]),
	"another rule in this rule group already uses the same FirewallDomainListId and Qtype",
	"Give the rules different Qtypes, or use one rule per domain list",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateFirewallRule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
	some i, r in _pf_r53r_frules(name)
	k := sprintf("%s|%v", [_pf_r53r_key(r, "FirewallDomainListId"), object.get(r, "Qtype", "")])
	dup := [1 |
		some o in _pf_r53r_frules(name)
		sprintf("%s|%v", [_pf_r53r_key(o, "FirewallDomainListId"), object.get(o, "Qtype", "")]) == k
	]
	count(dup) > 1
}
