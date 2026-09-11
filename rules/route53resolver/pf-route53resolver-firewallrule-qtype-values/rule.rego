package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrule-qtype-values", "ERROR", name,
	sprintf("Properties.FirewallRules[%d]", [i]),
	sprintf("Qtype is '%s', which is neither a supported record type nor a TYPENUMBER value", [q]),
	"Use a record type such as A, AAAA or TXT, or the TYPENUMBER form (for example TYPE65535)",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53resolver-firewallrulegroup-firewallrule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
	some i, r in _pf_r53r_frules(name)
	q := _pf_r53r_str(r, "Qtype")
	not upper(q) in _pf_r53r_qtypes
	not regex.match(`^TYPE[0-9]+$`, upper(q))
}
