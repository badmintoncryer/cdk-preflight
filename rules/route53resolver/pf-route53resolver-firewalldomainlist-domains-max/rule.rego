package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewalldomainlist-domains-max", "ERROR", name,
	"Properties.Domains",
	sprintf("the domain list declares %d domains; one request takes at most 1000", [n]),
	"Split the domains across several lists, or import them with DomainFileUrl",
	"https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_UpdateFirewallDomains.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallDomainList")
	n := count(_pf_r53r_arr(_pf_r53r_props(name), "Domains"))
	n > 1000
}
