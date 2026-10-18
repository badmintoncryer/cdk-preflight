package cdk_preflight

import rego.v1

# ArnResource belongs to the ARN type. A SINGLE with an ArnResource is rejected
# ("ARN resource can only be specified when the type is ARN").
violation contains make_diag_full("pf-vpclattice-rc-single-arn-definition", "ERROR", name,
	"Properties.ResourceConfigurationDefinition.ArnResource",
	"A SINGLE resource configuration uses ArnResource; the create fails with \"ARN resource can only be specified when the type is ARN\"",
	"Set ResourceConfigurationType to ARN, or define the SINGLE by an IpResource or a DnsResource",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/resource-configuration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	resolve(name, "Properties.ResourceConfigurationType") == "SINGLE"
	_pf_vpcl_has(name, "Properties.ResourceConfigurationDefinition.ArnResource")
}
