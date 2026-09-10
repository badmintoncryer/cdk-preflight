package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-rule-system-requires-domainname", "ERROR", name,
	"Properties.DomainName",
	"RuleType is SYSTEM but DomainName is missing (CloudFormation marks it optional, the API does not)",
	"Add the domain name the system rule should apply to",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-forwarding-outbound-queries.html#resolver-forwarding-outbound-queries-rule-values") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRule")
	p := _pf_r53r_props(name)
	_pf_r53r_str(p, "RuleType") == "SYSTEM"
	not _pf_r53r_has(p, "DomainName")
}
