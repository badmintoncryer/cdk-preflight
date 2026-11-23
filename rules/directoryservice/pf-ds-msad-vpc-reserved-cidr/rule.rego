package cdk_preflight

import rego.v1

# Getting started: "You cannot create a AWS Managed Microsoft AD in a VPC using addresses
# in the 198.18.0.0/15 address space." ETH0（AWS 側の管理ネットワーク）がこの範囲を使うため。
# VPC 自体はこの範囲で作れるので、ec2 側のルールでは拾えない。
_pf_dscidr_reserved := "198.18.0.0/15"

violation contains make_diag_full("pf-ds-msad-vpc-reserved-cidr", "ERROR", name,
	"Properties.VpcSettings.VpcId",
	sprintf("VPC %v uses CIDR %v, which overlaps 198.18.0.0/15; AWS Managed Microsoft AD cannot be created in a VPC using that address space", [vpc, cidr]),
	"Create the directory in a VPC whose CIDR does not overlap 198.18.0.0/15",
	"https://docs.aws.amazon.com/directoryservice/latest/admin-guide/ms_ad_getting_started.html") if {
	some name in resources_of_type("AWS::DirectoryService::MicrosoftAD")
	vpc := resolve(name, "Properties.VpcSettings.VpcId")
	is_string(vpc)
	vpc in resources_of_type("AWS::EC2::VPC")
	cidr := resolve(vpc, "Properties.CidrBlock")
	is_string(cidr)
	_pf_ec2lib_cidr_overlap(cidr, _pf_dscidr_reserved)
}
