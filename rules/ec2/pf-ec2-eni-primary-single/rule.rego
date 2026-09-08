package cdk_preflight

import rego.v1

_pf_ec2enip_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-networkinterface.html"

_pf_ec2enip_primaries(name) := [p |
	some p in flatten_list(name, "Properties.PrivateIpAddresses")
	coerce_to_bool(object.get(p.value, "Primary", false)) == true
]

violation contains make_diag_full("pf-ec2-eni-primary-single", "ERROR", name,
	"Properties.PrivateIpAddresses",
	sprintf("PrivateIpAddresses marks %v entries as Primary (\"Only one primary private IP address can be specified.\")", [count(ps)]),
	"Mark exactly one entry Primary and set the rest to false",
	_pf_ec2enip_url) if {
	some name in resources_of_type("AWS::EC2::NetworkInterface")
	ps := _pf_ec2enip_primaries(name)
	count(ps) > 1
}
