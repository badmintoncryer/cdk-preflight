package cdk_preflight

import rego.v1

# Every subnet of a resource gateway must belong to its VpcIdentifier ("Subnet
# subnet-... is not valid because it is not in VPC vpc-.... Specify a subnet in
# this VPC."). Checked for subnets in the same template.
violation contains make_diag_full("pf-vpclattice-rgw-subnet-other-vpc", "ERROR", name,
	sprintf("Properties.SubnetIds.%d", [it.index]),
	sprintf("Subnet '%s' is in VPC '%s', not '%s'; the create fails with \"is not valid because it is not in VPC\"", [s, sv, v]),
	"Use subnets of the resource gateway VPC",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceGateway.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceGateway")
	v := resolve(name, "Properties.VpcIdentifier")
	some it in flatten_list(name, "Properties.SubnetIds")
	s := resolve(name, sprintf("Properties.SubnetIds.%d", [it.index]))
	s in resources_of_type("AWS::EC2::Subnet")
	sv := resolve(s, "Properties.VpcId")
	_pf_vpcl_vpc_differs(sv, v)
}
