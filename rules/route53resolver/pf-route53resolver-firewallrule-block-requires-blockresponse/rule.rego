package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrule-block-requires-blockresponse", "ERROR", name,
	sprintf("Properties.FirewallRules[%d]", [i]),
	"Action is BLOCK but BlockResponse is missing",
	"Set BlockResponse to NODATA, NXDOMAIN or OVERRIDE",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53resolver-firewallrulegroup-firewallrule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
	some i, r in _pf_r53r_frules(name)
	_pf_r53r_str(r, "Action") == "BLOCK"
	not _pf_r53r_has(r, "BlockResponse")
}
