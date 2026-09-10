package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-route53resolver-firewalldomainlist-domain-format", "ERROR", name,
	"Properties.Domains",
	sprintf("domain '%s' puts * somewhere other than the first label", [d]),
	"Only use * as the leading label, as in *.example.com",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-user-managed-domain-lists.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallDomainList")
	some d in _pf_r53r_arr(_pf_r53r_props(name), "Domains")
	is_string(d)
	contains(d, "*")
	not startswith(d, "*")
}

violation contains make_diag_full("pf-route53resolver-firewalldomainlist-domain-format", "ERROR", name,
	"Properties.Domains",
	sprintf("domain '%s' contains a space or a non-ASCII character", [d]),
	"Use printable ASCII without spaces (punycode for internationalized names)",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-user-managed-domain-lists.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallDomainList")
	some d in _pf_r53r_arr(_pf_r53r_props(name), "Domains")
	is_string(d)
	not regex.match(`^[!-~]+$`, d)
}

violation contains make_diag_full("pf-route53resolver-firewalldomainlist-domain-format", "ERROR", name,
	"Properties.Domains",
	sprintf("domain '%s' starts with a dot", [d]),
	"Drop the leading dot",
	"https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-user-managed-domain-lists.html") if {
	some name in resources_of_type("AWS::Route53Resolver::FirewallDomainList")
	some d in _pf_r53r_arr(_pf_r53r_props(name), "Domains")
	is_string(d)
	startswith(d, ".")
}
