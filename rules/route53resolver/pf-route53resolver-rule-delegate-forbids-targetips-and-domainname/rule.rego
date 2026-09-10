package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-rule-delegate-forbids-targetips-and-domainname", "ERROR", name,
	"Properties.TargetIps",
	"RuleType is DELEGATE but TargetIps is set; delegate rules take neither target IPs nor a domain name",
	"Drop TargetIps",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverRule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRule")
	p := _pf_r53r_props(name)
	_pf_r53r_str(p, "RuleType") == "DELEGATE"
	_pf_r53r_has(p, "TargetIps")
}

violation contains make_diag_full("pf-route53resolver-rule-delegate-forbids-targetips-and-domainname", "ERROR", name,
	"Properties.DomainName",
	"RuleType is DELEGATE but DomainName is set; delegate rules take neither target IPs nor a domain name",
	"Drop DomainName",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverRule.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverRule")
	p := _pf_r53r_props(name)
	_pf_r53r_str(p, "RuleType") == "DELEGATE"
	_pf_r53r_has(p, "DomainName")
}
