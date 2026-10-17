package cdk_preflight

import rego.v1

# The security groups guard the association's endpoint in the VPC, so each one
# must belong to that VPC ("Security group is not valid for vpc vpc-...").
# Checked for security groups in the same template, and only when both VPCs are
# written the same way (both in-template VPCs, or both literal vpc- ids).
_pf_vpclsgv_kind(v) := "tpl" if v in resources_of_type("AWS::EC2::VPC")

_pf_vpclsgv_kind(v) := "lit" if {
	is_string(v)
	startswith(v, "vpc-")
	not v in resources_of_type("AWS::EC2::VPC")
}

violation contains make_diag_full("pf-vpclattice-snva-sg-other-vpc", "ERROR", name,
	sprintf("Properties.SecurityGroupIds.%d", [it.index]),
	sprintf("Security group '%s' is in VPC '%s', not '%s'; the create fails with \"Security group is not valid for vpc\"", [g, gv, v]),
	"Use security groups of the associated VPC",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateServiceNetworkVpcAssociation.html") if {
	some name in resources_of_type("AWS::VpcLattice::ServiceNetworkVpcAssociation")
	v := resolve(name, "Properties.VpcIdentifier")
	k := _pf_vpclsgv_kind(v)
	some it in flatten_list(name, "Properties.SecurityGroupIds")
	g := resolve(name, sprintf("Properties.SecurityGroupIds.%d", [it.index]))
	g in resources_of_type("AWS::EC2::SecurityGroup")
	gv := resolve(g, "Properties.VpcId")
	_pf_vpclsgv_kind(gv) == k
	gv != v
}
