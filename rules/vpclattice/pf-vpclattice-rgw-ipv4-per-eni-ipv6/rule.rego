package cdk_preflight

import rego.v1

# An IPv6-only gateway has no IPv4 addresses to hand out, so
# CreateResourceGateway rejects Ipv4AddressesPerEni with IpAddressType IPV6
# ("Can't provide value for field 'ipv4AddressesPerEni' with ipAddressType ==
# IPV6").
violation contains make_diag_full("pf-vpclattice-rgw-ipv4-per-eni-ipv6", "ERROR", name,
	"Properties.Ipv4AddressesPerEni",
	"Ipv4AddressesPerEni is set on an IPV6 resource gateway; the create fails with \"Can't provide value for field 'ipv4AddressesPerEni' with ipAddressType == IPV6\"",
	"Remove Ipv4AddressesPerEni, or use IpAddressType IPV4 or DUALSTACK",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/resource-gateway.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceGateway")
	resolve(name, "Properties.IpAddressType") == "IPV6"
	_pf_vpcl_has(name, "Properties.Ipv4AddressesPerEni")
}
