package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrulegroupassociation-priority-unique", "ERROR", name,
	"Properties.Priority",
	sprintf("priority %d is already used by another rule group association on the same VPC", [v]),
	"Give each association on the VPC its own priority",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53resolver-firewallrulegroupassociation.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroupAssociation")
	p := _pf_r53r_props(name)
	v := _pf_r53r_num(p, "Priority")
	k := sprintf("%s|%v", [_pf_r53r_key(p, "VpcId"), v])
	dup := [1 |
		some o in resources_of_type("AWS::Route53Resolver::FirewallRuleGroupAssociation")
		q := _pf_r53r_props(o)
		sprintf("%s|%v", [_pf_r53r_key(q, "VpcId"), _pf_r53r_num(q, "Priority")]) == k
	]
	count(dup) > 1
}
