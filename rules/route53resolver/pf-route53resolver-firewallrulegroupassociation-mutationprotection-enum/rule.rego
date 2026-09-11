package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewallrulegroupassociation-mutationprotection-enum", "ERROR", name,
	"Properties.MutationProtection",
	sprintf("MutationProtection is '%s'; only ENABLED and DISABLED are accepted", [v]),
	"Use ENABLED or DISABLED",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-route53resolver-firewallrulegroupassociation.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallRuleGroupAssociation")
	v := _pf_r53r_str(_pf_r53r_props(name), "MutationProtection")
	not v in {"ENABLED", "DISABLED"}
}
