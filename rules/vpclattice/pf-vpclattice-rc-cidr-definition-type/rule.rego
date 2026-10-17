package cdk_preflight

import rego.v1

# A CIDR resource configuration stands for address ranges, so its definition
# must be a CidrResource; an IpResource or DnsResource is rejected
# ("resourceConfigurationDefinition.cidrResource with cidrRanges must be provided
# for CIDR type").
violation contains make_diag_full("pf-vpclattice-rc-cidr-definition-type", "ERROR", name,
	sprintf("Properties.ResourceConfigurationDefinition.%s", [k]),
	sprintf("A CIDR resource configuration is defined by %s; the create fails with \"cidrResource with cidrRanges must be provided for CIDR type\"", [k]),
	"Use CidrResource with CidrRanges, or change ResourceConfigurationType to SINGLE",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/resource-configuration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	resolve(name, "Properties.ResourceConfigurationType") == "CIDR"
	some k in ["IpResource", "DnsResource"]
	_pf_vpcl_has(name, sprintf("Properties.ResourceConfigurationDefinition.%s", [k]))
}
