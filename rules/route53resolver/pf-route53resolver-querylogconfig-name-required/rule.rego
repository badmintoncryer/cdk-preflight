package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-querylogconfig-name-required", "ERROR", name,
	"Properties.Name",
	"Name is missing (CloudFormation marks it optional, the API requires at least one character)",
	"Give the query logging config a name",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverQueryLogConfig.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverQueryLoggingConfig")
	p := _pf_r53r_props(name)
	not _pf_r53r_has(p, "Name")
}

violation contains make_diag_full("pf-route53resolver-querylogconfig-name-required", "ERROR", name,
	"Properties.Name",
	"Name is an empty string",
	"Give the query logging config a name",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_CreateResolverQueryLogConfig.html") if {
	some name in resources_of_type("AWS::Route53Resolver::ResolverQueryLoggingConfig")
	_pf_r53r_str(_pf_r53r_props(name), "Name") == ""
}
