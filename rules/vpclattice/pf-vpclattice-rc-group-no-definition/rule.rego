package cdk_preflight

import rego.v1

# A GROUP has no resource of its own (its CHILD members do), so CreateResourceConfiguration rejects ResourceConfigurationDefinition on
# these types ("Unexpected attribute ... for type ...").
violation contains make_diag_full("pf-vpclattice-rc-group-no-definition", "ERROR", name,
	"Properties.ResourceConfigurationDefinition",
	sprintf("ResourceConfigurationDefinition is set on a %s resource configuration; the create fails with \"Unexpected attribute ... for type %s\"", [t, t]),
	"Remove ResourceConfigurationDefinition from the GROUP and define each resource in a CHILD",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceConfiguration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	t := resolve(name, "Properties.ResourceConfigurationType")
	t in {"GROUP"}
	_pf_vpcl_has(name, "Properties.ResourceConfigurationDefinition")
}
