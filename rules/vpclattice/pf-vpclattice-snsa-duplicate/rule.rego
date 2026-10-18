package cdk_preflight

import rego.v1

# The association has no name, so nothing in the schema stops a template from
# pairing the same service and service network twice; the second create fails
# ("Association for arn:...:servicenetwork/sn-... and arn:...:service/svc-...
# already exists"). Compared as written (logical ids or literals).
violation contains make_diag_full("pf-vpclattice-snsa-duplicate", "ERROR", name,
	"Properties.ServiceIdentifier",
	sprintf("Association '%s' already pairs service '%s' with service network '%s'; the create fails with \"Association for ... already exists\"", [other, s, n]),
	"Keep one association per service and service network",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/service-network-associations.html") if {
	some name in resources_of_type("AWS::VpcLattice::ServiceNetworkServiceAssociation")
	s := resolve(name, "Properties.ServiceIdentifier")
	n := resolve(name, "Properties.ServiceNetworkIdentifier")
	is_string(s)
	is_string(n)
	some other in resources_of_type("AWS::VpcLattice::ServiceNetworkServiceAssociation")
	other < name
	resolve(other, "Properties.ServiceIdentifier") == s
	resolve(other, "Properties.ServiceNetworkIdentifier") == n
}
