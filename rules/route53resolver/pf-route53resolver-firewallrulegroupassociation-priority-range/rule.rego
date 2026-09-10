package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrulegroupassociation-priority-range", "ERROR", name,
	"Properties.Priority",
	sprintf("Priority is %d; DNS Firewall reserves 100 and below and 9900 and above", [v]),
	"Use a priority between 101 and 9899",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53resolver-firewallrulegroupassociation.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroupAssociation")
	v := _pf_r53r_num(_pf_r53r_props(name), "Priority")
	is_number(v)
	_pf_r53r_outside_101_9899(v)
}
