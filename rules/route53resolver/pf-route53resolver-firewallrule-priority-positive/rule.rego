package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrule-priority-positive", "ERROR", name,
	sprintf("Properties.FirewallRules[%d]", [i]),
	sprintf("Priority is %d; DNS Firewall requires a priority greater than 0", [v]),
	"Use a priority of 1 or more",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53resolver-firewallrulegroup-firewallrule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
	some i, r in _pf_r53r_frules(name)
	v := _pf_r53r_num(r, "Priority")
	v <= 0
}
