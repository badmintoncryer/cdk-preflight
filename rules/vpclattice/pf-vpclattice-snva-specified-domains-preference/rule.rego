package cdk_preflight

import rego.v1

# A domain list means something only for the preferences that name specified
# domains. With ALL_DOMAINS or VERIFIED_DOMAINS_ONLY it is refused
# ("privateDnsSpecifiedDomains cannot be specified if privateDnsPreference is
# VERIFIED_DOMAINS_ONLY/ALL_DOMAINS"). An omitted preference is not flagged.
violation contains make_diag_full("pf-vpclattice-snva-specified-domains-preference", "ERROR", name,
	"Properties.DnsOptions.PrivateDnsSpecifiedDomains",
	sprintf("PrivateDnsSpecifiedDomains is set with PrivateDnsPreference %s; the create fails with \"privateDnsSpecifiedDomains cannot be specified if privateDnsPreference is VERIFIED_DOMAINS_ONLY/ALL_DOMAINS\"", [p]),
	"Use VERIFIED_DOMAINS_AND_SPECIFIED_DOMAINS or SPECIFIED_DOMAINS_ONLY, or remove PrivateDnsSpecifiedDomains",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_DnsOptions.html") if {
	some name in resources_of_type("AWS::VpcLattice::ServiceNetworkVpcAssociation")
	p := resolve(name, "Properties.DnsOptions.PrivateDnsPreference")
	p in {"ALL_DOMAINS", "VERIFIED_DOMAINS_ONLY"}
	_pf_vpcl_has(name, "Properties.DnsOptions.PrivateDnsSpecifiedDomains")
}
