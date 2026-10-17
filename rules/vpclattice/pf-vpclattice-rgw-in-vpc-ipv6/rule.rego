package cdk_preflight

import rego.v1

# CreateResourceGateway rejects ResourceConfigDnsResolution IN_VPC on an
# IPv6-only gateway ("IN_VPC DNS resolution is incompatible with IPv6 only IP
# address type.").
violation contains make_diag_full("pf-vpclattice-rgw-in-vpc-ipv6", "ERROR", name,
	"Properties.ResourceConfigDnsResolution",
	"An IPV6 resource gateway resolves DNS IN_VPC; the create fails with \"IN_VPC DNS resolution is incompatible with IPv6 only IP address type\"",
	"Use IpAddressType DUALSTACK or IPV4 for IN_VPC DNS resolution, or drop ResourceConfigDnsResolution IN_VPC",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/resource-gateway.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceGateway")
	resolve(name, "Properties.IpAddressType") == "IPV6"
	resolve(name, "Properties.ResourceConfigDnsResolution") == "IN_VPC"
}
