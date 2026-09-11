package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrulegroupassociation-max-per-vpc", "ERROR", name,
	"Properties.VpcId",
	sprintf("this template associates %d DNS Firewall rule groups with the same VPC; the limit is 5", [n]),
	"Associate at most 5 rule groups per VPC",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/DNSLimitations.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroupAssociation")
	k := _pf_r53r_key(_pf_r53r_props(name), "VpcId")
	n := count([1 |
		some o in resources_of_type("AWS::Route53Resolver::FirewallRuleGroupAssociation")
		_pf_r53r_key(_pf_r53r_props(o), "VpcId") == k
	])
	n > 5
}
