package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrule-dnsthreatprotection-enum", "ERROR", name,
	sprintf("Properties.FirewallRules[%d]", [i]),
	sprintf("DnsThreatProtection is '%s'; DNS Firewall only accepts DGA | DICTIONARY_DGA | DNS_TUNNELING", [v]),
	"Use one of DGA | DICTIONARY_DGA | DNS_TUNNELING",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53resolver-firewallrulegroup-firewallrule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
	some i, r in _pf_r53r_frules(name)
	v := _pf_r53r_str(r, "DnsThreatProtection")
	not v in {"DGA", "DICTIONARY_DGA", "DNS_TUNNELING"}
}
