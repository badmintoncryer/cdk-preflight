package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrule-redirectionaction-enum", "ERROR", name,
	sprintf("Properties.FirewallRules[%d]", [i]),
	sprintf("FirewallDomainRedirectionAction is '%s'; DNS Firewall only accepts INSPECT_REDIRECTION_DOMAIN | TRUST_REDIRECTION_DOMAIN", [v]),
	"Use one of INSPECT_REDIRECTION_DOMAIN | TRUST_REDIRECTION_DOMAIN",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-properties-route53resolver-firewallrulegroup-firewallrule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroup")
	some i, r in _pf_r53r_frules(name)
	v := _pf_r53r_str(r, "FirewallDomainRedirectionAction")
	not v in {"INSPECT_REDIRECTION_DOMAIN", "TRUST_REDIRECTION_DOMAIN"}
}
