package cdk_preflight

import rego.v1

# The engine validates subnet containment (E3059) and overlap (E3060)
# but accepts any VPC netmask; EC2 rejects anything outside /16../28.
violation contains make_diag_full("pf-ec2-vpc-cidr-block-size", "ERROR", name,
	"Properties.CidrBlock",
	sprintf("VPC CIDR block '%s' has netmask /%v; EC2 only accepts /16 through /28 (\"The CIDR '%s' is invalid.\")", [c, p, c]),
	"Use a netmask between /16 and /28",
	"https://docs.aws.amazon.com/vpc/latest/userguide/vpc-cidr-blocks.html") if {
	some name in resources_of_type("AWS::EC2::VPC")
	c := resolve(name, "Properties.CidrBlock")
	is_string(c)
	regex.match(`^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$`, c)
	p := to_number(split(c, "/")[1])
	_pf_ec2vcs_out(p)
}

_pf_ec2vcs_out(p) if p < 16

_pf_ec2vcs_out(p) if p > 28
