package cdk_preflight

import rego.v1

# A CHILD is a member of a GROUP and inherits its gateway, so CreateResourceConfiguration rejects the type without ResourceConfigurationGroupId
# ("ResourceConfigurationGroupId is required for CHILD type"; the CFN handler checks this itself). Absence is read from the raw document,
# so a value behind Fn::If is not flagged.
violation contains make_diag_full("pf-vpclattice-rc-child-requires-group", "ERROR", name,
	"Properties.ResourceConfigurationType",
	sprintf("A %s resource configuration has no ResourceConfigurationGroupId; the create fails with \"ResourceConfigurationGroupId is required for CHILD type\"", [t]),
	"Set ResourceConfigurationGroupId to the Id of a GROUP resource configuration (Fn::GetAtt <group>.Id)",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceConfiguration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	t := resolve(name, "Properties.ResourceConfigurationType")
	t in {"CHILD"}
	_pf_vpcl_raw(name, ["ResourceConfigurationGroupId"]) == "__pf_absent"
}
