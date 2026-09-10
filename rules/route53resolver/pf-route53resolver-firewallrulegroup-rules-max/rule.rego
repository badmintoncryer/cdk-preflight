package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrulegroup-rules-max", "ERROR", name,
	"Properties.FirewallRules",
	sprintf("the rule group declares %d rules; DNS Firewall allows at most 100", [n]),
	"Split the rules across several rule groups",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DNSLimitations.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
	n := count(_pf_r53r_frules(name))
	n > 100
}
