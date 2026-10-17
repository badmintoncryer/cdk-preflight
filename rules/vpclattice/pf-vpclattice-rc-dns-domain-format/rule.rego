package cdk_preflight

import rego.v1

# The schema bounds only the length of DnsResource.DomainName. CreateResourceConfiguration
# rejects a space or any non-ASCII character ("`api example.com` is not a valid
# resource configuration domain name"). Other hostname rules are not checked.
violation contains make_diag_full("pf-vpclattice-rc-dns-domain-format", "ERROR", name,
	"Properties.ResourceConfigurationDefinition.DnsResource.DomainName",
	sprintf("DnsResource.DomainName '%s' has a space or a non-ASCII character; the create fails with \"is not a valid resource configuration domain name\"", [d]),
	"Remove spaces and write an internationalized name in punycode (xn--...)",
	"https://docs.aws.amazon.com/vpc-lattice/latest/APIReference/API_CreateResourceConfiguration.html") if {
	some name in resources_of_type("AWS::VpcLattice::ResourceConfiguration")
	d := resolve(name, "Properties.ResourceConfigurationDefinition.DnsResource.DomainName")
	_pf_vpcl_bad_domain(d)
}
