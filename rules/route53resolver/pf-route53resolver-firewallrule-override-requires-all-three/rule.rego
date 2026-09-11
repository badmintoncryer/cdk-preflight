package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrule-override-requires-all-three", "ERROR", name,
	sprintf("Properties.FirewallRules[%d]", [i]),
	sprintf("BlockResponse is OVERRIDE but %s is missing; all of BlockOverrideDnsType, BlockOverrideDomain and BlockOverrideTtl are required", [k]),
	"Set BlockOverrideDnsType, BlockOverrideDomain and BlockOverrideTtl",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53resolver-firewallrulegroup-firewallrule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
	some i, r in _pf_r53r_frules(name)
	_pf_r53r_str(r, "BlockResponse") == "OVERRIDE"
	some k in {"BlockOverrideDnsType", "BlockOverrideDomain", "BlockOverrideTtl"}
	not _pf_r53r_has(r, k)
}
