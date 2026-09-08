package cdk_preflight

import rego.v1

_pf_ec2s6n_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-subnet.html"

_pf_ec2s6n_ipv4(name) if not _pf_ec2lib_absent(name, "CidrBlock")

_pf_ec2s6n_ipv4(name) if not _pf_ec2lib_absent(name, "Ipv4IpamPoolId")

violation contains make_diag_full("pf-ec2-subnet-ipv6-native-cidr", "ERROR", name,
	"Properties.Ipv6Native",
	"Ipv6Native is true but the subnet also carries IPv4 addressing (\"When specifying ipv4 parameters, cidrBlock or ipv4IpamPoolId, you cannot set ipv6Native to true.\")",
	"Drop CidrBlock / Ipv4IpamPoolId, or set Ipv6Native to false",
	_pf_ec2s6n_url) if {
	some name in resources_of_type("AWS::EC2::Subnet")
	coerce_to_bool(resolve(name, "Properties.Ipv6Native")) == true
	_pf_ec2s6n_ipv4(name)
}
