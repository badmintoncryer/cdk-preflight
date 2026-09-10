package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewalldomainlist-domains-fileurl-exclusive", "ERROR", name,
	"Properties.DomainFileUrl",
	"both Domains and DomainFileUrl are set; a domain list is filled from one or the other",
	"Keep either the inline Domains or the DomainFileUrl import",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-user-managed-domain-lists.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallDomainList")
	p := _pf_r53r_props(name)
	_pf_r53r_has(p, "Domains")
	_pf_r53r_has(p, "DomainFileUrl")
}
