package cdk_preflight

import rego.v1

# A SINGLE stands for one IP address or DNS name, so CreateResourceConfiguration rejects the type without ResourceConfigurationDefinition
# ("Missing expected ... for type ..."). Absence is read from the raw document,
# so a value behind Fn::If is not flagged.
violation contains make_diag_full("pf-vpclattice-rc-single-definition-required", "ERROR", name,
	"Properties.ResourceConfigurationType",
	sprintf("A %s resource configuration has no ResourceConfigurationDefinition; the create fails with \"Missing expected ... for type %s\"", [t, t]),
	"Add ResourceConfigurationDefinition with an IpResource or a DnsResource",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceConfiguration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	t := resolve(name, "Properties.ResourceConfigurationType")
	t in {"SINGLE"}
	_pf_vpcl_raw(name, ["ResourceConfigurationDefinition"]) == "__pf_absent"
}
