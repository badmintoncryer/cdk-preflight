package cdk_preflight

import rego.v1

# A resource configuration with AllowAssociationToSharableServiceNetwork false
# cannot join a service network whose SharingConfig is enabled ("Resource
# Configuration does not allow for association to a service network that can be
# shared."). Checked when both are in the same template and written explicitly.
violation contains make_diag_full("pf-vpclattice-snra-sharable-sn", "ERROR", name,
	"Properties.ServiceNetworkId",
	sprintf("Resource configuration '%s' disallows sharable service networks and '%s' has sharing enabled; the association fails with \"does not allow for association to a service network that can be shared\"", [c, s]),
	"Set AllowAssociationToSharableServiceNetwork to true, or associate a service network with SharingConfig enabled false",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/resource-configuration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ServiceNetworkResourceAssociation")
	c := resolve(name, "Properties.ResourceConfigurationId")
	c in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	resolve(c, "Properties.AllowAssociationToSharableServiceNetwork") == false
	s := resolve(name, "Properties.ServiceNetworkId")
	s in resources_of_type("AWS::VpcLattice::ServiceNetwork")
	resolve(s, "Properties.SharingConfig.enabled") == true
}
