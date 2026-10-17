package cdk_preflight

import rego.v1

# The two preferences that name specified domains need the list
# ("privateDnsSpecifiedDomains must be specified if privateDnsPreference is
# VERIFIED_DOMAINS_AND_SPECIFIED_DOMAINS/SPECIFIED_DOMAINS_ONLY"). Absence is
# read from the raw document, so a list behind Fn::If is not flagged.
violation contains make_diag_full("pf-vpclattice-snva-specified-only-requires-domains", "ERROR", name,
	"Properties.DnsOptions.PrivateDnsPreference",
	sprintf("PrivateDnsPreference %s has no PrivateDnsSpecifiedDomains; the create fails with \"privateDnsSpecifiedDomains must be specified if privateDnsPreference is VERIFIED_DOMAINS_AND_SPECIFIED_DOMAINS/SPECIFIED_DOMAINS_ONLY\"", [p]),
	"Add PrivateDnsSpecifiedDomains, or use ALL_DOMAINS or VERIFIED_DOMAINS_ONLY",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_DnsOptions.html") if {
	some name in resources_of_type("AWS::VpcLattice::ServiceNetworkVpcAssociation")
	p := resolve(name, "Properties.DnsOptions.PrivateDnsPreference")
	p in {"SPECIFIED_DOMAINS_ONLY", "VERIFIED_DOMAINS_AND_SPECIFIED_DOMAINS"}
	_pf_vpcl_raw(name, ["DnsOptions", "PrivateDnsSpecifiedDomains"]) == "__pf_absent"
}
