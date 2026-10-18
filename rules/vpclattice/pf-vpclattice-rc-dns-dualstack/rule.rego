package cdk_preflight

import rego.v1

# The schema enum for DnsResource.IpAddressType includes DUALSTACK, but the
# service takes IPV4 or IPV6 only ("DUALSTACK is not a valid DNS name IP address
# type. Valid options are [IPv4, IPv6]").
violation contains make_diag_full("pf-vpclattice-rc-dns-dualstack", "ERROR", name,
	"Properties.ResourceConfigurationDefinition.DnsResource.IpAddressType",
	"DnsResource.IpAddressType is DUALSTACK; the create fails with \"DUALSTACK is not a valid DNS name IP address type\"",
	"Use IPV4 or IPV6",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_DnsResource.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	resolve(name, "Properties.ResourceConfigurationDefinition.DnsResource.IpAddressType") == "DUALSTACK"
}
