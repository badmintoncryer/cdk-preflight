package cdk_preflight

import rego.v1

violation contains make_diag_full("pf-ec2-vpc-cidr-block-overlap", "ERROR", name,
	"Properties.CidrBlock",
	sprintf("CidrBlock %s overlaps the primary CIDR %s of VPC '%s' (\"CidrConflict: CIDR range conflicts\")", [c, primary, vref]),
	"Choose a secondary range that does not overlap the primary CIDR",
	"https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-ec2-vpccidrblock.html") if {
	some name in resources_of_type("AWS::EC2::VPCCidrBlock")
	c := resolve(name, "Properties.CidrBlock")
	is_string(c)
	vref := resolve(name, "Properties.VpcId")
	is_string(vref)
	vref in resources_of_type("AWS::EC2::VPC")
	primary := resolve(vref, "Properties.CidrBlock")
	is_string(primary)
	_pf_ec2lib_cidr_overlap(c, primary)
}
