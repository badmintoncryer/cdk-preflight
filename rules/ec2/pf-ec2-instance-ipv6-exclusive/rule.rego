package cdk_preflight

import rego.v1

_pf_ec2i6_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-instance.html"

violation contains make_diag_full("pf-ec2-instance-ipv6-exclusive", "ERROR", name,
	"Properties.Ipv6AddressCount",
	"Ipv6AddressCount and Ipv6Addresses cannot both be set (\"IPv6 addresses and IPv6 address count may not be specified on the same request\")",
	"Keep either the count or the explicit address list",
	_pf_ec2i6_url) if {
	some name in resources_of_type("AWS::EC2::Instance")
	not _pf_ec2lib_absent(name, "Ipv6AddressCount")
	count(flatten_list(name, "Properties.Ipv6Addresses")) > 0
}
