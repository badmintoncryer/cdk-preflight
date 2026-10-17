package cdk_preflight

import rego.v1

# An IPV6 or DUALSTACK gateway takes IPv6 addresses from its subnets, so a
# subnet without an IPv6 block is rejected ("Subnet subnet-... is not valid
# because it doesn't have IPv6 blocks"). Checked for subnets in the same
# template that set none of Ipv6CidrBlock / Ipv6IpamPoolId / Ipv6NetmaskLength /
# Ipv6Native and get no AWS::EC2::SubnetCidrBlock.
_pf_vpclrgw6_keys := ["Ipv6CidrBlock", "Ipv6IpamPoolId", "Ipv6NetmaskLength", "Ipv6Native"]

_pf_vpclrgw6_v6(s) if {
	some k in _pf_vpclrgw6_keys
	_pf_vpcl_raw(s, [k]) != "__pf_absent"
}

_pf_vpclrgw6_v6(s) if {
	some b in resources_of_type("AWS::EC2::SubnetCidrBlock")
	resolve(b, "Properties.SubnetId") == s
}

violation contains make_diag_full("pf-vpclattice-rgw-ipv6-subnet-family", "ERROR", name,
	sprintf("Properties.SubnetIds.%d", [it.index]),
	sprintf("Subnet '%s' has no IPv6 block but the gateway is %s; the create fails with \"doesn't have IPv6 blocks\"", [s, t]),
	"Use subnets with an IPv6 CIDR block, or IpAddressType IPV4",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/resource-gateway.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceGateway")
	t := resolve(name, "Properties.IpAddressType")
	t in {"IPV6", "DUALSTACK"}
	some it in flatten_list(name, "Properties.SubnetIds")
	s := resolve(name, sprintf("Properties.SubnetIds.%d", [it.index]))
	s in resources_of_type("AWS::EC2::Subnet")
	not _pf_vpclrgw6_v6(s)
}
