package cdk_preflight

import rego.v1

# Every security group of a resource gateway must belong to its VpcIdentifier
# ("Security group sg-... is not valid because it is not in VPC vpc-....
# Specify a security group in this VPC."). Checked for security groups in the
# same template.
violation contains make_diag_full("pf-vpclattice-rgw-sg-other-vpc", "ERROR", name,
	sprintf("Properties.SecurityGroupIds.%d", [it.index]),
	sprintf("Security group '%s' is in VPC '%s', not '%s'; the create fails with \"is not valid because it is not in VPC\"", [g, gv, v]),
	"Use security groups of the resource gateway VPC",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceGateway.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceGateway")
	v := resolve(name, "Properties.VpcIdentifier")
	some it in flatten_list(name, "Properties.SecurityGroupIds")
	g := resolve(name, sprintf("Properties.SecurityGroupIds.%d", [it.index]))
	g in resources_of_type("AWS::EC2::SecurityGroup")
	gv := resolve(g, "Properties.VpcId")
	_pf_vpcl_vpc_differs(gv, v)
}
