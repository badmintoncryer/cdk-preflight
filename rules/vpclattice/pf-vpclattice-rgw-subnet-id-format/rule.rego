package cdk_preflight

import rego.v1

# The schema puts no pattern on SubnetIds[], but CreateResourceGateway rejects
# anything that is not a subnet id ("SubnetId vpc-4331593e has invalid format").
# Literal strings without the subnet- prefix only; Ref / Fn::GetAtt are not
# checked.
violation contains make_diag_full("pf-vpclattice-rgw-subnet-id-format", "ERROR", name,
	sprintf("Properties.SubnetIds.%d", [i]),
	sprintf("SubnetIds entry '%s' is not a subnet id; the create fails with \"SubnetId %s has invalid format\"", [s, s]),
	"Use subnet ids (subnet-...) of the gateway VPC",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceGateway.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceGateway")
	l := _pf_vpcl_raw(name, ["SubnetIds"])
	is_array(l)
	some i, s in l
	is_string(s)
	not startswith(s, "subnet-")
}
