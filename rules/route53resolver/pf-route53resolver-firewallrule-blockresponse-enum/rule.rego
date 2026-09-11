package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrule-blockresponse-enum", "ERROR", name,
	sprintf("Properties.FirewallRules[%d]", [i]),
	sprintf("BlockResponse is '%s'; DNS Firewall only accepts NODATA | NXDOMAIN | OVERRIDE", [v]),
	"Use one of NODATA | NXDOMAIN | OVERRIDE",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53resolver-firewallrulegroup-firewallrule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
	some i, r in _pf_r53r_frules(name)
	v := _pf_r53r_str(r, "BlockResponse")
	not v in {"NODATA", "NXDOMAIN", "OVERRIDE"}
}
