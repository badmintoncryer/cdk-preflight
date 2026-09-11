package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrule-override-attrs-require-override", "ERROR", name,
	sprintf("Properties.FirewallRules[%d]", [i]),
	sprintf("BlockResponse is %s but %s is set; override properties only apply to OVERRIDE", [b, k]),
	"Drop the BlockOverride properties, or set BlockResponse to OVERRIDE",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53resolver-firewallrulegroup-firewallrule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
	some i, r in _pf_r53r_frules(name)
	b := _pf_r53r_str(r, "BlockResponse")
	b in {"NODATA", "NXDOMAIN"}
	some k in {"BlockOverrideDnsType", "BlockOverrideDomain", "BlockOverrideTtl"}
	_pf_r53r_has(r, k)
}
