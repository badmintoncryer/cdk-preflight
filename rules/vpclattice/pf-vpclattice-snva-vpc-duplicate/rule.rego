package cdk_preflight

import rego.v1

# A VPC joins at most one service network (a non-adjustable quota), so a
# second association of the same VPC fails ("VPC has already been associated to
# a service network"). Associations in one template are compared by
# VpcIdentifier as written (the same logical id or the same literal).
violation contains make_diag_full("pf-vpclattice-snva-vpc-duplicate", "ERROR", name,
	"Properties.VpcIdentifier",
	sprintf("VPC '%s' is already associated by '%s'; the create fails with \"VPC has already been associated to a service network\"", [v, other]),
	"Associate each VPC with one service network only",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/quotas.html") if {
	some name in resources_of_type("AWS::VpcLattice::ServiceNetworkVpcAssociation")
	v := resolve(name, "Properties.VpcIdentifier")
	is_string(v)
	some other in resources_of_type("AWS::VpcLattice::ServiceNetworkVpcAssociation")
	other < name
	resolve(other, "Properties.VpcIdentifier") == v
}
