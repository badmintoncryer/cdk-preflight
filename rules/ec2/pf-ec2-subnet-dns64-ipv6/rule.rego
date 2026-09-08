package cdk_preflight

import rego.v1

_pf_ec2dns64_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-subnet.html"

_pf_ec2dns64_v6keys := ["Ipv6CidrBlock", "Ipv6CidrBlocks", "Ipv6IpamPoolId", "Ipv6Native"]

violation contains make_diag_full("pf-ec2-subnet-dns64-ipv6", "ERROR", name,
	"Properties.EnableDns64",
	"EnableDns64 is set on a subnet with no IPv6 CIDR (\"Cannot set enable-dns64 to true unless the subnet has an IPv6 CIDR block associated with it\")",
	"Give the subnet an IPv6 CIDR (Ipv6CidrBlock / Ipv6CidrBlocks / Ipv6IpamPoolId) or drop EnableDns64",
	_pf_ec2dns64_url) if {
	some name in resources_of_type("AWS::EC2::Subnet")
	on := resolve(name, "Properties.EnableDns64")
	on in [true, "true"]
	every key in _pf_ec2dns64_v6keys {
		_pf_ec2lib_absent(name, key)
	}
}
