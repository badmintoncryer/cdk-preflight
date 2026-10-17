package cdk_preflight

import rego.v1

# A CHILD is reached through its GROUP, so associating the CHILD itself is
# rejected ("Resource Configuration of type child cannot be associated to service
# network."). Checked when the resource configuration is in the same template.
violation contains make_diag_full("pf-vpclattice-snra-child-rc", "ERROR", name,
	"Properties.ResourceConfigurationId",
	sprintf("Resource configuration '%s' is a CHILD; the association fails with \"Resource Configuration of type child cannot be associated to service network\"", [c]),
	"Associate the GROUP resource configuration instead of its CHILD",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/resource-configuration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ServiceNetworkResourceAssociation")
	c := resolve(name, "Properties.ResourceConfigurationId")
	c in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	resolve(c, "Properties.ResourceConfigurationType") == "CHILD"
}
