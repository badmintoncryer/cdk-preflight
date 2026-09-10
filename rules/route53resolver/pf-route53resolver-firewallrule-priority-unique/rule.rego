package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrule-priority-unique", "ERROR", name,
	sprintf("Properties.FirewallRules[%d]", [i]),
	sprintf("priority %d is used by more than one rule in this rule group", [v]),
	"Give each rule in the group its own priority",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53resolver-firewallrulegroup-firewallrule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
	some i, r in _pf_r53r_frules(name)
	v := _pf_r53r_num(r, "Priority")
	dup := [1 | some o in _pf_r53r_frules(name); _pf_r53r_num(o, "Priority") == v]
	count(dup) > 1
}
