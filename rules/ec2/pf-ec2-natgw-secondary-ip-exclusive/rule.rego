package cdk_preflight

import rego.v1

_pf_ec2ngs_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-natgateway.html"

violation contains make_diag_full("pf-ec2-natgw-secondary-ip-exclusive", "ERROR", name,
	"Properties.SecondaryPrivateIpAddressCount",
	"SecondaryPrivateIpAddressCount cannot be combined with SecondaryPrivateIpAddresses",
	"Keep either the count or the explicit list",
	_pf_ec2ngs_url) if {
	some name in resources_of_type("AWS::EC2::NatGateway")
	not _pf_ec2lib_absent(name, "SecondaryPrivateIpAddressCount")
	count(flatten_list(name, "Properties.SecondaryPrivateIpAddresses")) > 0
}
