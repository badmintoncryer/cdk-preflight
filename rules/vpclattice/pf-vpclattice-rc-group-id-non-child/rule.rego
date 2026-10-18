package cdk_preflight

import rego.v1

# Only a CHILD belongs to a group, so CreateResourceConfiguration rejects ResourceConfigurationGroupId on
# these types ("Unexpected attribute ... for type ...").
violation contains make_diag_full("pf-vpclattice-rc-group-id-non-child", "ERROR", name,
	"Properties.ResourceConfigurationGroupId",
	sprintf("ResourceConfigurationGroupId is set on a %s resource configuration; the create fails with \"Unexpected attribute ... for type %s\"", [t, t]),
	"Remove ResourceConfigurationGroupId, or make the resource configuration a CHILD",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceConfiguration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	t := resolve(name, "Properties.ResourceConfigurationType")
	t in {"SINGLE", "GROUP", "ARN"}
	_pf_vpcl_has(name, "Properties.ResourceConfigurationGroupId")
}
