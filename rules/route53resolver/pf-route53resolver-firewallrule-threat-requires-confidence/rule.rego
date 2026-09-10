package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrule-threat-requires-confidence", "ERROR", name,
	sprintf("Properties.FirewallRules[%d]", [i]),
	"DnsThreatProtection and ConfidenceThreshold must be present together",
	"Set both, or neither",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53resolver-firewallrulegroup-firewallrule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
	some i, r in _pf_r53r_frules(name)
	count({k | some k in {"DnsThreatProtection", "ConfidenceThreshold"}; _pf_r53r_has(r, k)}) == 1
}
