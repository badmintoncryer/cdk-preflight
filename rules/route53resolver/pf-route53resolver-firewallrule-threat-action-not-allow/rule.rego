package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrule-threat-action-not-allow", "ERROR", name,
	sprintf("Properties.FirewallRules[%d]", [i]),
	"the threat protection rule sets Action ALLOW; only ALERT and BLOCK are accepted",
	"Use ALERT or BLOCK",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53resolver-firewallrulegroup-firewallrule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
	some i, r in _pf_r53r_frules(name)
	_pf_r53r_has(r, "DnsThreatProtection")
	_pf_r53r_str(r, "Action") == "ALLOW"
}
