package cdk_preflight

import rego.v1

_pf_ec2vcr_url := "https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpc.html"

# 実測で拒否されるのはこの 4 レンジだけ。240.0.0.0/4（クラス E）と
# 100.64.0.0/10（CGNAT）は受理されるので入れない。
_pf_ec2vcr_reserved := ["0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4"]

violation contains make_diag_full("pf-ec2-vpc-cidr-reserved-range", "ERROR", name,
	"Properties.CidrBlock",
	sprintf("VPC CIDR %v overlaps the reserved range %v (\"The CIDR '%v' is invalid.\")", [cidr, reserved, cidr]),
	"Use a CIDR outside 0.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16 and 224.0.0.0/4",
	_pf_ec2vcr_url) if {
	some name in resources_of_type("AWS::EC2::VPC")
	cidr := resolve(name, "Properties.CidrBlock")
	is_string(cidr)
	some reserved in _pf_ec2vcr_reserved
	_pf_ec2lib_cidr_overlap(cidr, reserved)
}
