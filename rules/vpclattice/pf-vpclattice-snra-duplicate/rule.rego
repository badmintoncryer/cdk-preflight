package cdk_preflight

import rego.v1

# The association has no name, so nothing in the schema stops a template from
# pairing the same resource configuration and service network twice; the second
# create fails ("Association for sn-... and rcfg-... already exists."). Compared
# as written (logical ids or literals).
violation contains make_diag_full("pf-vpclattice-snra-duplicate", "ERROR", name,
	"Properties.ResourceConfigurationId",
	sprintf("Association '%s' already pairs resource configuration '%s' with service network '%s'; the create fails with \"Association for ... already exists\"", [other, c, s]),
	"Keep one association per resource configuration and service network",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/service-network-associations.html") if {
	some name in resources_of_type("AWS::VpcLattice::ServiceNetworkResourceAssociation")
	c := resolve(name, "Properties.ResourceConfigurationId")
	s := resolve(name, "Properties.ServiceNetworkId")
	is_string(c)
	is_string(s)
	some other in resources_of_type("AWS::VpcLattice::ServiceNetworkResourceAssociation")
	other < name
	resolve(other, "Properties.ResourceConfigurationId") == c
	resolve(other, "Properties.ServiceNetworkId") == s
}
