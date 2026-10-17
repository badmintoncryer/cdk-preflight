package cdk_preflight

import rego.v1

# DnsOptions tunes private DNS, so it is refused when private DNS is off
# ("privateDnsPreference/privateDnsSpecifiedDomains cannot be specified if
# privateDnsEnabled is false"). Only an explicit PrivateDnsEnabled false is
# flagged.
violation contains make_diag_full("pf-vpclattice-snva-dns-options-requires-private-dns", "ERROR", name,
	"Properties.DnsOptions",
	"DnsOptions is set while PrivateDnsEnabled is false; the create fails with \"privateDnsPreference/privateDnsSpecifiedDomains cannot be specified if privateDnsEnabled is false\"",
	"Set PrivateDnsEnabled to true, or remove DnsOptions",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_DnsOptions.html") if {
	some name in resources_of_type("AWS::VpcLattice::ServiceNetworkVpcAssociation")
	resolve(name, "Properties.PrivateDnsEnabled") in {false, "false"}
	some k in ["PrivateDnsPreference", "PrivateDnsSpecifiedDomains"]
	_pf_vpcl_has(name, sprintf("Properties.DnsOptions.%s", [k]))
}
