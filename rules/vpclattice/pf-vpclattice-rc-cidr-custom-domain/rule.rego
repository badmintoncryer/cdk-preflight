package cdk_preflight

import rego.v1

# A CIDR resource configuration covers address ranges and has no single name,
# so CreateResourceConfiguration rejects CustomDomainName on it ("Unexpected
# attribute customDomainName for type CIDR").
violation contains make_diag_full("pf-vpclattice-rc-cidr-custom-domain", "ERROR", name,
	"Properties.CustomDomainName",
	"CustomDomainName is set on a CIDR resource configuration; the create fails with \"Unexpected attribute customDomainName for type CIDR\"",
	"Remove CustomDomainName from the CIDR resource configuration",
	"https://docs.aws.amazon.com/vpc-lattice/latest/ug/resource-configuration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	resolve(name, "Properties.ResourceConfigurationType") == "CIDR"
	_pf_vpcl_has(name, "Properties.CustomDomainName")
}
