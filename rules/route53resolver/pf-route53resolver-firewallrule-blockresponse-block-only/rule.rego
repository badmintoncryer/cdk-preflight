package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrule-blockresponse-block-only", "ERROR", name,
	sprintf("Properties.FirewallRules[%d]", [i]),
	sprintf("Action is %s but BlockResponse is set; block options only apply to BLOCK rules", [a]),
	"Drop BlockResponse, or set Action to BLOCK",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53resolver-firewallrulegroup-firewallrule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
	some i, r in _pf_r53r_frules(name)
	a := _pf_r53r_str(r, "Action")
	a in {"ALLOW", "ALERT"}
	_pf_r53r_has(r, "BlockResponse")
}
